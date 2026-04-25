module Main where

import Data.List (isPrefixOf)
import Data.SafeCopy (safeGet, safePut)
import Data.Serialize (runGet, runPut)

import Test.Tasty
import Test.Tasty.HUnit

import Distribution.Server.Framework.AuthCrypt
import Distribution.Server.Framework.AuthTypes
import Distribution.Server.Users.Types (UserName (..))

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "PasswordTests"
  [ typeClassificationTests
  , safeCopyRoundTripTests
  , argon2idHashingTests
  , checkAndUpgradeTests
  ]

typeClassificationTests :: TestTree
typeClassificationTests = testGroup "PasswdHash type classification"
  [ testCase "mkPasswdHash with argon2id prefix -> Argon2idPasswdHash" $
      let hash = mkPasswdHash "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash"
       in case hash of
            Argon2idPasswdHash _ -> pure ()
            LegacyPasswdHash _   -> assertFailure "expected Argon2idPasswdHash, got LegacyPasswdHash"
  , testCase "mkPasswdHash with legacy string -> LegacyPasswdHash" $
      let hash = mkPasswdHash "abc123deadbeef"
       in case hash of
            LegacyPasswdHash _   -> pure ()
            Argon2idPasswdHash _ -> assertFailure "expected LegacyPasswdHash, got Argon2idPasswdHash"
  , testCase "isArgon2idHash True for Argon2idPasswdHash" $
      isArgon2idHash (mkPasswdHash "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash") @?= True
  , testCase "isArgon2idHash False for LegacyPasswdHash" $
      isArgon2idHash (mkPasswdHash "abc123deadbeef") @?= False
  , testCase "passwdHashToString . mkPasswdHash === id (legacy)" $
      let s = "abc123deadbeef"
       in passwdHashToString (mkPasswdHash s) @?= s
  , testCase "passwdHashToString . mkPasswdHash === id (argon2id)" $
      let s = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash"
       in passwdHashToString (mkPasswdHash s) @?= s
  ]

safeCopyRoundTripTests :: TestTree
safeCopyRoundTripTests = testGroup "SafeCopy round-trip"
  [ testCase "LegacyPasswdHash round-trip" $
      let original = LegacyPasswdHash "abc123deadbeef"
          encoded  = runPut (safePut original)
          decoded  = runGet safeGet encoded
       in decoded @?= Right original
  , testCase "Argon2idPasswdHash round-trip" $
      let original = mkPasswdHash "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash"
          encoded  = runPut (safePut original)
          decoded  = runGet safeGet encoded
       in decoded @?= Right original
  , testCase "mkPasswdHash . passwdHashToString === id (legacy)" $
      let h = LegacyPasswdHash "abc123deadbeef"
       in mkPasswdHash (passwdHashToString h) @?= h
  , testCase "mkPasswdHash . passwdHashToString === id (argon2id)" $
      let h = mkPasswdHash "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash"
       in mkPasswdHash (passwdHashToString h) @?= h
  ]

argon2idHashingTests :: TestTree
argon2idHashingTests = testGroup "newPasswdHashArgon2id"
  [ testCase "produces Argon2idPasswdHash" $ do
      result <- newPasswdHashArgon2id (PasswdPlain "hunter2")
      case result of
        Argon2idPasswdHash _ -> pure ()
        LegacyPasswdHash _   -> assertFailure "expected Argon2idPasswdHash"
  , testCase "hash string starts with $argon2id$" $ do
      result <- newPasswdHashArgon2id (PasswdPlain "hunter2")
      assertBool "hash must start with $argon2id$" $
        "$argon2id$" `isPrefixOf` passwdHashToString result
  , testCase "two hashes of same password differ (random salt)" $ do
      h1 <- newPasswdHashArgon2id (PasswdPlain "hunter2")
      h2 <- newPasswdHashArgon2id (PasswdPlain "hunter2")
      assertBool "hashes must differ due to random salt" (h1 /= h2)
  ]

checkAndUpgradeTests :: TestTree
checkAndUpgradeTests = testGroup "checkAndUpgradePasswd"
  [ testCase "legacy + correct password -> PasswordMatchUpgrade" $ do
      let realm = RealmName "hackage"
          user  = UserName "testuser"
          plain = PasswdPlain "secretpass"
          legacy = newPasswdHash realm user plain
      result <- checkAndUpgradePasswd realm user plain legacy
      case result of
        PasswordMatchUpgrade (Argon2idPasswdHash _) -> pure ()
        PasswordMatchUpgrade (LegacyPasswdHash _)   ->
          assertFailure "upgrade hash should be Argon2idPasswdHash"
        PasswordMatchOk   -> assertFailure "expected PasswordMatchUpgrade"
        PasswordMismatch  -> assertFailure "expected PasswordMatchUpgrade"
  , testCase "legacy + wrong password -> PasswordMismatch" $ do
      let realm  = RealmName "hackage"
          user   = UserName "testuser"
          legacy = newPasswdHash realm user (PasswdPlain "correct")
      result <- checkAndUpgradePasswd realm user (PasswdPlain "wrong") legacy
      result @?= PasswordMismatch
  , testCase "argon2id + correct password -> PasswordMatchOk" $ do
      let plain = PasswdPlain "secretpass"
      Argon2idPasswdHash stored <- newPasswdHashArgon2id plain
      let hash = Argon2idPasswdHash stored
      result <- checkAndUpgradePasswd (RealmName "hackage") (UserName "testuser") plain hash
      result @?= PasswordMatchOk
  , testCase "argon2id + wrong password -> PasswordMismatch" $ do
      let plain = PasswdPlain "secretpass"
      Argon2idPasswdHash stored <- newPasswdHashArgon2id plain
      let hash = Argon2idPasswdHash stored
      result <- checkAndUpgradePasswd (RealmName "hackage") (UserName "testuser") (PasswdPlain "wrongpass") hash
      result @?= PasswordMismatch
  ]
