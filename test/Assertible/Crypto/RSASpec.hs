{-# LANGUAGE OverloadedStrings #-}
module Assertible.Crypto.RSASpec (spec) where

import           Test.Hspec

import           Assertible.Crypto.RSA

spec :: Spec
spec = do
    describe "decrypt" $ do
        it "recovers plain text from cipher text" $ do
            (publicKey, privateKey) <- generateKeyPair
            Right message <- encrypt publicKey "foo"
            decrypt privateKey message `shouldBe` Right "foo"
