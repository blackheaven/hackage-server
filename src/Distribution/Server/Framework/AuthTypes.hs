{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, TemplateHaskell #-}
module Distribution.Server.Framework.AuthTypes where

import Data.List (isPrefixOf)
import qualified Data.Password.Argon2 as Password
import Distribution.Server.Framework.MemSize
import qualified Data.Text as T

import Data.SafeCopy (SafeCopy (..), base, contain, deriveSafeCopy, safeGet, safePut)

-- | A plain, unhashed password. Careful what you do with them.
--
newtype PasswdPlain = PasswdPlain String
  deriving Eq

-- | A password hash. Supports both legacy MD5 and modern Argon2id formats.
--
-- Legacy hashes are stored in the format
-- @md5 (username ++ ":" ++ realm ++ ":" ++ password)@.
--
-- Argon2id hashes use the PHC string format from @Data.Password.Argon2@.
data PasswdHash
  = DigestPasswdHash !String
  | Argon2idPasswdHash !(Password.PasswordHash Password.Argon2)
  deriving (Eq, Ord, Show)

mkPasswdHash :: String -> PasswdHash
mkPasswdHash s
  | "$argon2id$" `isPrefixOf` s = Argon2idPasswdHash (Password.PasswordHash (T.pack s))
  | otherwise = DigestPasswdHash s

passwdHashToString :: PasswdHash -> String
passwdHashToString (DigestPasswdHash s) = s
passwdHashToString (Argon2idPasswdHash h) = T.unpack (Password.unPasswordHash h)

isArgon2idHash :: PasswdHash -> Bool
isArgon2idHash Argon2idPasswdHash {} = True
isArgon2idHash _ = False

instance MemSize PasswdHash where
  memSize (DigestPasswdHash s) = memSize1 s
  memSize (Argon2idPasswdHash h) = memSize1 (Password.unPasswordHash h)

instance SafeCopy PasswdHash where
  putCopy = contain . safePut . passwdHashToString
  getCopy = contain $ fmap mkPasswdHash safeGet
  version = 0
  kind = base

newtype RealmName = RealmName String
  deriving (Show, Eq)

$(deriveSafeCopy 0 'base ''PasswdPlain)
