module Assertible.Crypto.Util where

import           Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as Base64
import           Data.Text (Text)
import           Data.Text.Encoding (decodeUtf8, encodeUtf8)

base64Encode :: ByteString -> Text
base64Encode = decodeUtf8 . Base64.encode

base64Decode :: Text -> Either String ByteString
base64Decode = Base64.decode . encodeUtf8
