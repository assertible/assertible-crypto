{-# LANGUAGE QuasiQuotes #-}
module Assertible.Crypto.Sql.Migration where

import           Database.PostgreSQL.Simple.SqlQQ
import           Database.PostgreSQL.Simple.Types

create_table_api_encryption_key :: Query
create_table_api_encryption_key = [sql|

CREATE TABLE api_encryption_key (
    api UUID UNIQUE NOT NULL -- REFERENCES api ON DELETE CASCADE ON UPDATE CASCADE
  , public_key BYTEA NOT NULL
  , private_key BYTEA NOT NULL
  , iv BYTEA NOT NULL
  );
|]
