# Snowflake Native App distribution lane

This is the provider-side build, validation, image, and release contract for the
agent-bom Snowflake Native App with Snowpark Container Services (SPCS). The
repository can make a release review-ready and publish a release directive after
the protected environment is configured. Snowflake alone can approve the
provider and Marketplace listing for external consumers.

## Repository-controlled dry run

First command:

```bash
python scripts/release/snowflake_native_app.py validate
```

Build the reproducible package:

```bash
python scripts/release/snowflake_native_app.py package \
  --output dist/agent-bom-snowflake-v0_96_3.tgz
```

Artifact: the command prints the SHA-256 digest of a deterministic archive that
contains only the files declared by `snowflake.yml`. The package excludes image
archives, credentials, provider bootstrap SQL, `images.yml`, and `snowflake.yml`.

Next step: dispatch `.github/workflows/release-snowflake.yml` with
`dry_run=true`. It validates the Snowflake CLI project, packages the app, builds
all four `linux/amd64` images from `images.yml`, and uploads immutable workflow
artifacts without contacting Snowflake.

## Protected provider release

The `snowflake-marketplace` GitHub environment owns the only live path. Configure
these protected values:

- secrets: `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_PRIVATE_KEY`
- variables: `SNOWFLAKE_ROLE`, `SNOWFLAKE_WAREHOUSE`,
  `SNOWFLAKE_IMAGE_REPOSITORY_URL`

Use a dedicated Snowflake service user with key-pair authentication. The workflow
writes the key to an ephemeral `0600` file, never prints it, and removes it in an
`always()` step.

With `dry_run=false`, the workflow:

1. creates the provider database, schema, and image repository if absent;
2. authenticates Docker with `snow spcs image-registry login`;
3. loads and pushes all four version-pinned images;
4. deploys the package from `deploy/snowflake/native-app/snowflake.yml`; and
5. publishes the selected `QA`, `ALPHA`, or `DEFAULT` release channel through
   `snow app publish`.

The default remains `dry_run=true`; live publication also requires approval for
the protected GitHub environment.

## Exact external-only boundary

Repository work cannot complete these account- and Snowflake-controlled steps:

1. Accept the Snowflake Provider Terms of Service for an application package
   using `DISTRIBUTION=EXTERNAL`.
2. Obtain Snowflake Product Security approval to publish an app with containers.
   This is mandatory before creating a public or private listing. An unapproved
   provider receives Snowflake error `093197` and must submit Snowflake's security
   questionnaire.
3. Pass Snowflake's automated/manual security review for the exact application
   version and its four images.
4. Configure the provider profile and legal terms, create the listing in
   Provider Studio, attach the application package, select targets, and submit
   the listing for Snowflake review.
5. Wait for Snowflake approval and confirm availability from a separate consumer
   account before describing the app as Marketplace-published.

Authoritative Snowflake references:

- [Secure a Native App with SPCS](https://docs.snowflake.com/en/developer-guide/native-apps/security-na-spcs)
- [Native App security review](https://docs.snowflake.com/en/developer-guide/native-apps/security-overview)
- [Marketplace app listing requirements](https://docs.snowflake.com/collaboration/guidelines-reqs-for-listing-apps)
- [Declare app resources in marketplace.yml](https://docs.snowflake.com/en/developer-guide/native-apps/marketplace-file)
- [Publish with release channels](https://docs.snowflake.com/en/developer-guide/native-apps/release-channels)
- [Snowflake CLI `snow app publish`](https://docs.snowflake.com/en/developer-guide/snowflake-cli/command-reference/native-apps-commands/publish-app)

## Listing and consumer evidence

The review-ready listing content is versioned at
`docs/snowflake-native-app/listing-template.yml`. The consumer-visible resource
contract is `deploy/snowflake/native-app/marketplace.yml`; it declares the
`AGENT_BOM_CONSUMER_POOL` compute requirement, and `scripts/setup.sql` creates that pool
during installation.

Before submitting a listing, install in a private-preview account and retain the
output of:

```sql
CALL agent_bom.core.health_check();
SHOW SERVICES IN APPLICATION agent_bom;
SHOW EXTERNAL ACCESS INTEGRATIONS LIKE 'AGENT_BOM_%';
```

Expected state:

- API/UI service is present and authenticated through Snowflake.
- scanner and MCP runtime services remain absent until their enable procedures
  are called;
- advisory EAIs remain unbound until the consumer approves them; and
- bound customer objects have read-only grants only.
