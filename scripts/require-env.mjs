// Fails fast when a required environment variable is missing, so a test run
// that needs Postgres cannot silently skip it.
const missing = process.argv.slice(2).filter((name) => !process.env[name]);
if (missing.length > 0) {
  console.error(`Set ${missing.join(", ")} first, for example:\n  export AGG_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres`);
  process.exit(2);
}
