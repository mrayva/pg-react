pub fn is_compatible_extension_version(version: &str) -> bool {
    if version == "0.31.0"
        || version == "0.32.0"
        || version == "0.33.0"
        || version == "0.34.0"
        || version == "0.35.0"
        || version == "0.36.0"
        || version == "0.37.0"
        || version == "0.38.0"
        || version == "0.39.0"
        || version == "0.40.0"
        || version == "0.41.0"
        || version == "0.42.0"
        || version == "0.43.0"
        || version == "0.43.1"
        || version == "0.43.2"
        || version == "0.43.3"
        || version == "0.44.0"
        || version == "0.45.0"
        || version == "0.46.0"
        || version == "0.46.1"
        || version == "0.46.2"
        || version == "1.0.0"
    {
        return true;
    }
    if let Some(rest) = version.strip_prefix("1.0.0-rc.")
        && !rest.is_empty()
        && rest.chars().all(|c| c.is_ascii_digit())
        && !(rest.starts_with('0') && rest.len() > 1)
        && let Ok(n) = rest.parse::<u32>()
    {
        return n >= 1;
    }
    false
}

#[cfg(feature = "pg18")]
use pgrx::bgworkers::{BackgroundWorker, BackgroundWorkerBuilder, SignalWakeFlags};
#[cfg(feature = "pg18")]
use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};
#[cfg(feature = "pg18")]
use pgrx::prelude::*;
#[cfg(feature = "pg18")]
use std::collections::BTreeSet;
#[cfg(feature = "pg18")]
use std::ffi::CString;
#[cfg(feature = "pg18")]
use std::time::Duration;

#[cfg(feature = "pg18")]
static DATABASES: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
#[cfg(feature = "pg18")]
static WORKER_ROLE: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(Some(c"postgres"));
#[cfg(feature = "pg18")]
static POLL_INTERVAL_MS: GucSetting<i32> = GucSetting::<i32>::new(1_000);
#[cfg(feature = "pg18")]
static BATCH_SIZE: GucSetting<i32> = GucSetting::<i32>::new(32);
#[cfg(feature = "pg18")]
static MAX_PENDING_JOBS: GucSetting<i32> = GucSetting::<i32>::new(10_000);

#[cfg(feature = "pg18")]
#[pg_guard]
pub extern "C-unwind" fn _PG_init() {
    GucRegistry::define_string_guc(
        c"pg_react.databases",
        c"Databases served by PostgreSQL-managed pg-react workers.",
        c"Comma-separated database names; changing this setting requires a PostgreSQL restart.",
        &DATABASES,
        GucContext::Postmaster,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        c"pg_react.worker_role",
        c"Database role used by PostgreSQL-managed pg-react workers.",
        c"The role must be able to connect to every configured pg_react.databases entry.",
        &WORKER_ROLE,
        GucContext::Postmaster,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        c"pg_react.poll_interval_ms",
        c"Managed worker polling interval.",
        c"Milliseconds between managed coordination and execution cycles.",
        &POLL_INTERVAL_MS,
        10,
        60_000,
        GucContext::Sighup,
        GucFlags::UNIT_MS,
    );
    GucRegistry::define_int_guc(
        c"pg_react.batch_size",
        c"Maximum managed maintenance batch size.",
        c"Window maintenance uses this bound; managed job claims retain the public 100-item maximum.",
        &BATCH_SIZE,
        1,
        1_000,
        GucContext::Sighup,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        c"pg_react.max_pending_jobs",
        c"Pending-job backpressure threshold.",
        c"Managed workers drain existing work but pause coordination at this threshold.",
        &MAX_PENDING_JOBS,
        1,
        i32::MAX,
        GucContext::Sighup,
        GucFlags::default(),
    );

    if !unsafe { pg_sys::process_shared_preload_libraries_in_progress } {
        return;
    }
    let Some(databases) = DATABASES.get() else {
        return;
    };
    for database in databases
        .to_string_lossy()
        .split(',')
        .map(str::trim)
        .filter(|database| !database.is_empty())
        .collect::<BTreeSet<_>>()
    {
        BackgroundWorkerBuilder::new(&format!("pg-react managed: {database}"))
            .set_library("pg_react")
            .set_function("pg_react_managed_main")
            .set_extra(database)
            .enable_spi_access()
            .set_restart_time(Some(Duration::from_secs(1)))
            .load();
    }
}

#[cfg(feature = "pg18")]
#[pg_guard]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn pg_react_managed_main(_arg: pg_sys::Datum) {
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
    let database = BackgroundWorker::get_extra();
    let role = WORKER_ROLE.get().expect("pg_react.worker_role");
    BackgroundWorker::connect_worker_to_spi(Some(database), Some(&role.to_string_lossy()));

    loop {
        if BackgroundWorker::sighup_received() {
            unsafe { pg_sys::ProcessConfigFile(pg_sys::GucContext::PGC_SIGHUP) };
        }
        BackgroundWorker::transaction(|| {
            assert_eq!(
                Spi::get_one::<bool>("SELECT session_user = current_user")
                    .expect("check managed worker login identity"),
                Some(true),
                "managed worker must begin each cycle as its configured login",
            );
            let version = Spi::get_one::<String>(
                "SELECT extversion FROM pg_extension WHERE extname = 'pg_react'",
            )
            .expect("query pg_react extension version");
            if let Some(v) = version
                && is_compatible_extension_version(&v)
            {
                let worker_role = Spi::get_one::<String>(
                        r#"SELECT CASE WHEN count(DISTINCT candidate.oid) = 1
                                  THEN max(pg_catalog.quote_ident(candidate.rolname)) END
                           FROM pg_catalog.pg_proc AS proc
                           CROSS JOIN LATERAL pg_catalog.aclexplode(
                               COALESCE(proc.proacl, pg_catalog.acldefault('f', proc.proowner))) AS access
                           JOIN pg_catalog.pg_roles AS candidate ON candidate.oid = access.grantee
                           WHERE proc.oid = 'pgreact_api.managed_cycle()'::pg_catalog.regprocedure
                             AND access.privilege_type = 'EXECUTE'
                             AND access.grantee NOT IN (0, proc.proowner)
                             AND pg_catalog.pg_has_role(session_user, candidate.oid, 'SET')"#,
                    )
                    .expect("look up configured managed worker role")
                    .expect("managed worker role must be a unique SET-capable function grantee");
                Spi::run(&format!("SET LOCAL ROLE {worker_role}"))
                    .expect("assume configured managed worker role");
                Spi::run("SELECT pgreact_api.managed_cycle()").expect("run pg-react managed cycle");
                Spi::run("RESET ROLE").expect("restore managed worker login role");
                assert_eq!(
                    Spi::get_one::<bool>("SELECT session_user = current_user")
                        .expect("check restored managed worker login identity"),
                    Some(true),
                    "managed cycle must restore its configured login role",
                );
            }
        });
        if !BackgroundWorker::wait_latch(Some(Duration::from_millis(POLL_INTERVAL_MS.get() as u64)))
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_compatibility() {
        // Supported transition & GA versions
        assert!(is_compatible_extension_version("0.31.0"));
        assert!(is_compatible_extension_version("0.32.0"));
        assert!(is_compatible_extension_version("0.33.0"));
        assert!(is_compatible_extension_version("0.34.0"));
        assert!(is_compatible_extension_version("0.35.0"));
        assert!(is_compatible_extension_version("0.36.0"));
        assert!(is_compatible_extension_version("0.37.0"));
        assert!(is_compatible_extension_version("0.38.0"));
        assert!(is_compatible_extension_version("0.39.0"));
        assert!(is_compatible_extension_version("0.40.0"));
        assert!(is_compatible_extension_version("0.41.0"));
        assert!(is_compatible_extension_version("0.42.0"));
        assert!(is_compatible_extension_version("0.43.0"));
        assert!(is_compatible_extension_version("0.43.1"));
        assert!(is_compatible_extension_version("0.43.2"));
        assert!(is_compatible_extension_version("0.43.3"));
        assert!(is_compatible_extension_version("0.44.0"));
        assert!(is_compatible_extension_version("0.45.0"));
        assert!(is_compatible_extension_version("0.46.0"));
        assert!(is_compatible_extension_version("0.46.1"));
        assert!(is_compatible_extension_version("0.46.2"));
        assert!(!is_compatible_extension_version("0.46.2"));
        assert!(is_compatible_extension_version("1.0.0-rc.1"));
        assert!(is_compatible_extension_version("1.0.0-rc.2"));
        assert!(is_compatible_extension_version("1.0.0-rc.42"));
        assert!(is_compatible_extension_version("1.0.0"));

        // Unsupported pre-v1 versions
        assert!(!is_compatible_extension_version("0.30.0"));
        assert!(!is_compatible_extension_version("0.29.0"));
        assert!(!is_compatible_extension_version("0.1.0"));

        // Unsupported post-1.0 or future-major versions
        assert!(!is_compatible_extension_version("1.0.1"));
        assert!(!is_compatible_extension_version("1.1.0"));
        assert!(!is_compatible_extension_version("2.0.0"));

        // Malformed or invalid version strings
        assert!(!is_compatible_extension_version("1.0.0-rc.0"));
        assert!(!is_compatible_extension_version("1.0.0-rc.01"));
        assert!(!is_compatible_extension_version("1.0.0-rc"));
        assert!(!is_compatible_extension_version("1.0.0-rc."));
        assert!(!is_compatible_extension_version("1.0.0-rc.1a"));
        assert!(!is_compatible_extension_version("1.0.0-beta.1"));
        assert!(!is_compatible_extension_version("v1.0.0"));
        assert!(!is_compatible_extension_version("1.0.0.0"));
        assert!(!is_compatible_extension_version(""));
        assert!(!is_compatible_extension_version("random_string"));
    }
}
