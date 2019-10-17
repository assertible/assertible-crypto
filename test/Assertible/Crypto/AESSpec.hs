{-# LANGUAGE OverloadedStrings #-}
module Assertible.Crypto.AESSpec (spec) where

import           Test.Hspec

import           Assertible.Crypto.AES

spec :: Spec
spec = do
    describe "decrypt" $ do
        it "recovers plain text from cipher text" $ do
            secretKey <- generateKey
            (iv, encryptedMsg) <- encrypt secretKey "foo"
            decrypt secretKey iv encryptedMsg `shouldReturn` "foo"
