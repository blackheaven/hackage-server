module Distribution.Server.Features.Vouch.Types where

data VouchError
  = You'reTooNew
  | VoucheeAlreadyUploader
  | AlreadySufficientlyVouched
  | YouAlreadyVouched
  deriving (Show, Eq)

data VouchSuccess = AddVouchComplete | AddVouchIncomplete Int
  deriving (Show, Eq)
