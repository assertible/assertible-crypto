{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeSynonymInstances #-}
module Assertible.Crypto.RSA (
  PublicKey
, PrivateKey
, generateKeyPair
, decrypt

, encryptPrivateKey
, decryptPrivateKey
, encodePublicKey

, encrypt -- used by test suite only
) where

import           Crypto.Hash.Algorithms (SHA256 (..))
import           Crypto.PubKey.RSA
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import           Data.Bifunctor
import           Data.ByteString (ByteString)
import           Data.Text (Text)
import           Data.Text.Encoding (decodeUtf8, encodeUtf8)
import           Data.X509

import qualified Assertible.Crypto.AES as AES
import           Assertible.Crypto.Util

generateKeyPair :: IO (PublicKey, PrivateKey)
generateKeyPair = generate 256 0x10001

oaepParams :: OAEP.OAEPParams SHA256 ByteString ByteString
oaepParams = OAEP.defaultOAEPParams SHA256

encrypt :: PublicKey -> Text -> IO (Either String Text)
encrypt key input = bimap show base64Encode <$> OAEP.encrypt oaepParams key (encodeUtf8 input)

decrypt :: PrivateKey -> Text -> Either String Text
decrypt key input = base64Decode input >>= bimap show decodeUtf8 . OAEP.decrypt Nothing oaepParams key

encryptPrivateKey :: AES.MasterKey -> PrivateKey -> IO (AES.IV AES.AES128, ByteString)
encryptPrivateKey masterKey key = AES.encrypt masterKey (encodePrivateKey key)

decryptPrivateKey :: AES.MasterKey -> AES.IV AES.AES128 -> ByteString -> IO PrivateKey
decryptPrivateKey masterKey iv key = do
    x <- AES.decrypt masterKey iv key
    either error return $ decodePrivateKey x

encodePublicKey :: PublicKey -> ByteString
encodePublicKey key = encodeKey (PubKeyRSA key)

encodePrivateKey :: PrivateKey -> ByteString
encodePrivateKey key = encodeKey (PrivKeyRSA key)

encodeKey :: ASN1Object a => a -> ByteString
encodeKey key = encodeASN1' DER $ toASN1 key []

decodePrivateKey :: ByteString -> Either String PrivateKey
decodePrivateKey input = decodeKey input >>= \ case
    PrivKeyRSA key -> Right key
    _ -> Left "unexpected key type"

decodeKey :: ASN1Object a => ByteString -> Either String a
decodeKey input = case decodeASN1' DER input of
    Right xs -> case fromASN1 xs of
        Right (key, []) -> Right key
        Right _ -> Left "encountered unconsumed ASN1 input while decoding key"
        Left err -> Left err
    Left err -> Left (show err)
