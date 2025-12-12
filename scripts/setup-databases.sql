-- LUX Network Explorer Database Setup
-- Run as postgres superuser: psql -U postgres -f setup-databases.sql

-- Create blockscout user if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'blockscout') THEN
        CREATE ROLE blockscout WITH LOGIN PASSWORD 'blockscout';
    END IF;
END
$$;

-- Grant necessary privileges
ALTER ROLE blockscout CREATEDB;

-- =============================================
-- C-Chain Databases (Blockscout)
-- =============================================

-- LUX Mainnet
CREATE DATABASE explorer_luxnet OWNER blockscout;
CREATE DATABASE stats_luxnet OWNER blockscout;

-- LUX Testnet
CREATE DATABASE explorer_luxtest OWNER blockscout;
CREATE DATABASE stats_luxtest OWNER blockscout;

-- LUX Devnet
CREATE DATABASE explorer_luxdev OWNER blockscout;
CREATE DATABASE stats_luxdev OWNER blockscout;

-- ZOO Mainnet
CREATE DATABASE explorer_zoonet OWNER blockscout;
CREATE DATABASE stats_zoonet OWNER blockscout;

-- ZOO Testnet
CREATE DATABASE explorer_zootest OWNER blockscout;
CREATE DATABASE stats_zootest OWNER blockscout;

-- =============================================
-- A-Chain Databases (AI Chain - Custom Indexer)
-- =============================================

-- A-Chain Mainnet
CREATE DATABASE explorer_achain OWNER blockscout;

-- A-Chain Testnet
CREATE DATABASE explorer_achain_test OWNER blockscout;

-- =============================================
-- B-Chain Databases (Bridge Chain - Custom Indexer)
-- =============================================

-- B-Chain Mainnet
CREATE DATABASE explorer_bchain OWNER blockscout;

-- B-Chain Testnet
CREATE DATABASE explorer_bchain_test OWNER blockscout;

-- =============================================
-- P-Chain Databases (Platform Chain - Custom Indexer)
-- =============================================

-- P-Chain Mainnet
CREATE DATABASE explorer_pchain OWNER blockscout;

-- P-Chain Testnet
CREATE DATABASE explorer_pchain_test OWNER blockscout;

-- =============================================
-- Q-Chain Databases (Quantum Chain - Custom Indexer)
-- =============================================

-- Q-Chain Mainnet
CREATE DATABASE explorer_qchain OWNER blockscout;

-- Q-Chain Testnet
CREATE DATABASE explorer_qchain_test OWNER blockscout;

-- =============================================
-- T-Chain Databases (Teleport Chain - Custom Indexer)
-- =============================================

-- T-Chain Mainnet
CREATE DATABASE explorer_tchain OWNER blockscout;

-- T-Chain Testnet
CREATE DATABASE explorer_tchain_test OWNER blockscout;

-- =============================================
-- X-Chain Databases (Exchange Chain - Custom Indexer)
-- =============================================

-- X-Chain Mainnet
CREATE DATABASE explorer_xchain OWNER blockscout;

-- X-Chain Testnet
CREATE DATABASE explorer_xchain_test OWNER blockscout;

-- =============================================
-- Z-Chain Databases (ZK Chain - Custom Indexer)
-- =============================================

-- Z-Chain Mainnet
CREATE DATABASE explorer_zchain OWNER blockscout;

-- Z-Chain Testnet
CREATE DATABASE explorer_zchain_test OWNER blockscout;

-- =============================================
-- Grant Schema Permissions
-- =============================================

-- Function to grant schema permissions
CREATE OR REPLACE FUNCTION grant_schema_permissions(db_name TEXT) RETURNS VOID AS $$
BEGIN
    EXECUTE format('GRANT ALL PRIVILEGES ON DATABASE %I TO blockscout', db_name);
END;
$$ LANGUAGE plpgsql;

-- Apply permissions to all C-Chain databases
SELECT grant_schema_permissions('explorer_luxnet');
SELECT grant_schema_permissions('explorer_luxtest');
SELECT grant_schema_permissions('explorer_luxdev');
SELECT grant_schema_permissions('explorer_zoonet');
SELECT grant_schema_permissions('explorer_zootest');
SELECT grant_schema_permissions('stats_luxnet');
SELECT grant_schema_permissions('stats_luxtest');
SELECT grant_schema_permissions('stats_luxdev');
SELECT grant_schema_permissions('stats_zoonet');
SELECT grant_schema_permissions('stats_zootest');

-- Apply permissions to all custom chain databases
SELECT grant_schema_permissions('explorer_achain');
SELECT grant_schema_permissions('explorer_achain_test');
SELECT grant_schema_permissions('explorer_bchain');
SELECT grant_schema_permissions('explorer_bchain_test');
SELECT grant_schema_permissions('explorer_pchain');
SELECT grant_schema_permissions('explorer_pchain_test');
SELECT grant_schema_permissions('explorer_qchain');
SELECT grant_schema_permissions('explorer_qchain_test');
SELECT grant_schema_permissions('explorer_tchain');
SELECT grant_schema_permissions('explorer_tchain_test');
SELECT grant_schema_permissions('explorer_xchain');
SELECT grant_schema_permissions('explorer_xchain_test');
SELECT grant_schema_permissions('explorer_zchain');
SELECT grant_schema_permissions('explorer_zchain_test');

-- Clean up
DROP FUNCTION grant_schema_permissions(TEXT);

-- Summary
\echo '=========================================='
\echo 'LUX Network Explorer Databases Created:'
\echo '=========================================='
\echo ''
\echo 'C-Chain (Blockscout EVM):'
\echo '  - explorer_luxnet, stats_luxnet (LUX Mainnet)'
\echo '  - explorer_luxtest, stats_luxtest (LUX Testnet)'
\echo '  - explorer_luxdev, stats_luxdev (LUX Devnet)'
\echo '  - explorer_zoonet, stats_zoonet (ZOO Mainnet)'
\echo '  - explorer_zootest, stats_zootest (ZOO Testnet)'
\echo ''
\echo 'A-Chain (AI - Providers, Tasks, Attestations):'
\echo '  - explorer_achain (Mainnet)'
\echo '  - explorer_achain_test (Testnet)'
\echo ''
\echo 'B-Chain (Bridge - MPC, Cross-chain):'
\echo '  - explorer_bchain (Mainnet)'
\echo '  - explorer_bchain_test (Testnet)'
\echo ''
\echo 'P-Chain (Platform - Validators, Staking):'
\echo '  - explorer_pchain (Mainnet)'
\echo '  - explorer_pchain_test (Testnet)'
\echo ''
\echo 'Q-Chain (Quantum - Stamps, Finality):'
\echo '  - explorer_qchain (Mainnet)'
\echo '  - explorer_qchain_test (Testnet)'
\echo ''
\echo 'T-Chain (Teleport - Warp Messages):'
\echo '  - explorer_tchain (Mainnet)'
\echo '  - explorer_tchain_test (Testnet)'
\echo ''
\echo 'X-Chain (Exchange - Assets, UTXOs):'
\echo '  - explorer_xchain (Mainnet)'
\echo '  - explorer_xchain_test (Testnet)'
\echo ''
\echo 'Z-Chain (ZK - Proofs, Confidential):'
\echo '  - explorer_zchain (Mainnet)'
\echo '  - explorer_zchain_test (Testnet)'
\echo ''
\echo 'Total: 24 databases'
\echo '=========================================='
