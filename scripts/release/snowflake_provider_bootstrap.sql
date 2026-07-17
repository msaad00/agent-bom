-- Provider-account objects used only to build and publish the Native App.
-- This file is not part of the consumer application package.
CREATE DATABASE IF NOT EXISTS agent_bom_provider;
CREATE SCHEMA IF NOT EXISTS agent_bom_provider.spcs;
CREATE IMAGE REPOSITORY IF NOT EXISTS agent_bom_provider.spcs.agent_bom_repo
    COMMENT = 'Version-pinned agent-bom Snowpark Container Services images';
