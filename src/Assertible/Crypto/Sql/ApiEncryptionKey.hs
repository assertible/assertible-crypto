{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE QuasiQuotes #-}
module Assertible.Crypto.Sql.ApiEncryptionKey (
  MasterKey
, getPublicApiEncryptionKey
, getPrivateApiEncryptionKey
) where

import           Assertible.Crypto.AES
import           Assertible.Crypto.RSA
import           Control.Monad
import qualified Data.ByteArray as BA
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Maybe
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.SqlQQ
import           Database.PostgreSQL.Simple.ToField

getPublicApiEncryptionKey :: ToField api => MasterKey -> api -> Connection -> IO ByteString
getPublicApiEncryptionKey masterKey api conn = do
    (key, _, _) <- getApiEncryptionKey masterKey api conn
    return key

getPrivateApiEncryptionKey :: ToField api => MasterKey -> api -> Connection -> IO PrivateKey
getPrivateApiEncryptionKey masterKey api conn = do
    (_, privateKey, binaryIV) <- getApiEncryptionKey masterKey api conn
    iv <- binaryToIv binaryIV
    decryptPrivateKey masterKey iv (fromBinary privateKey)

getApiEncryptionKey :: ToField api => MasterKey -> api -> Connection -> IO (ByteString, Binary ByteString, Binary ByteString)
getApiEncryptionKey masterKey api conn = do
    selectApiEncryptionKey api conn >>= \ case
        Just key -> return key
        Nothing -> do
            (publicKey, privateKey_) <- generateKeyPair

            (iv, privateKey) <- encryptPrivateKey masterKey privateKey_

            insertApiEncryptionKey api publicKey (Binary privateKey) iv conn

            -- IMPORTANT: We need to query the key from the database here as a
            -- concurrent process may have been faster than us.
            getApiEncryptionKey masterKey api conn

selectApiEncryptionKey :: ToField api => api -> Connection -> IO (Maybe (ByteString, Binary ByteString, Binary ByteString))
selectApiEncryptionKey api conn = fmap listToMaybe $ query conn [sql|
SELECT public_key, private_key, iv FROM api_encryption_key WHERE api = ?
|] (Only api)

insertApiEncryptionKey :: ToField api => api -> PublicKey -> Binary ByteString -> IV AES128 -> Connection -> IO ()
insertApiEncryptionKey api publicKey privateKey iv conn = void $ execute conn [sql|
INSERT INTO api_encryption_key (api,public_key,private_key,iv) VALUES (?,?,?,?) ON CONFLICT (api) DO NOTHING
|] (api, publicKeyToBinary publicKey, privateKey, ivToBinary iv)

ivToBinary :: IV AES128 -> Binary ByteString
ivToBinary = Binary . B.pack . BA.unpack

binaryToIv :: Binary ByteString -> IO (IV AES128)
binaryToIv = makeIV . fromBinary

publicKeyToBinary :: PublicKey -> Binary ByteString
publicKeyToBinary = Binary . encodePublicKey
