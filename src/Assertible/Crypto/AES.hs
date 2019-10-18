{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Assertible.Crypto.AES (
  MasterKey
, decodeMasterKey

, IV
, AES128
, makeIV

, encrypt
, decrypt

, generateKey -- used in .env.sample
) where

import           Crypto.Cipher.AES
import           Crypto.Cipher.Types hiding (makeIV)
import qualified Crypto.Cipher.Types as Crypto
import           Crypto.Error
import           Crypto.Random.Types
import           Data.ByteString (ByteString)
import           Data.Text (Text)
import qualified Data.Text as T
import qualified GHC.Err as Base

import           Assertible.Crypto.Util

data MasterKey = MasterKey ByteString

instance Show MasterKey where
    show (MasterKey key) = T.unpack (base64Encode key)

decodeMasterKey :: Text -> Either String MasterKey
decodeMasterKey = fmap MasterKey . base64Decode

size :: Int
size = blockSize (Base.undefined :: AES128)

generateKey :: IO MasterKey
generateKey = MasterKey <$> getRandomBytes size

generateIV :: IO (IV AES128)
generateIV = getRandomBytes size >>= makeIV

makeIV :: ByteString -> IO (IV AES128)
makeIV binaryIV = case Crypto.makeIV binaryIV of
    Nothing -> error "invalid IV"
    Just iv -> return iv

encrypt :: MasterKey -> ByteString -> IO (IV AES128, ByteString)
encrypt key message = do
    iv <- generateIV
    (,) iv <$> ctr key iv message

decrypt :: MasterKey -> IV AES128 -> ByteString -> IO ByteString
decrypt = ctr

ctr :: MasterKey -> IV AES128 -> ByteString -> IO ByteString
ctr (MasterKey key) iv message = case cipherInit key of
    CryptoFailed e -> error (show e)
    CryptoPassed aes -> return $ ctrCombine aes iv message
