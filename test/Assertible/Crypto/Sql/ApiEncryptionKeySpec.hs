{-# LANGUAGE OverloadedStrings #-}
module Assertible.Crypto.Sql.ApiEncryptionKeySpec (spec) where

import           Assertible.Crypto.AES
import           Assertible.Crypto.Sql.ApiEncryptionKey
import           Assertible.Crypto.Sql.Migration
import           Control.Exception
import           Data.UUID.Types
import           Database.PostgreSQL.Simple
import           Test.Hspec

connectInfo :: ConnectInfo
connectInfo = defaultConnectInfo {
  connectUser = "assertible"
, connectPassword = "assertible"
, connectDatabase = "assertible_crypto_test"
}

withTestDb :: (Connection -> IO a) -> IO a
withTestDb action = bracket (connect connectInfo) close $ \ conn -> do
    bracket_ (begin conn) (rollback conn) $ do
        _ <- execute_ conn create_table_api_encryption_key
        action conn

spec :: Spec
spec = around withTestDb $ do
    describe "getPrivateApiEncryptionKey" $ do
        it "returns the same key on every invocation" $ \ conn -> do

            let api = nil
            masterKey <- either error return (decodeMasterKey "3U1bBHQKSszXl1BHs2SV1A==")

            key <- getPrivateApiEncryptionKey masterKey api conn
            getPrivateApiEncryptionKey masterKey api conn `shouldReturn` key
