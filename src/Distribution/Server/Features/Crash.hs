{-# LANGUAGE RecordWildCards #-}
module Distribution.Server.Features.Crash (serverCrashFeature) where

import Distribution.Server.Framework
import Distribution.Server.Features.Users (UserFeature(..))

import Data.Maybe
import Control.Exception
import Control.Concurrent

serverCrashFeature :: UserFeature -> HackageFeature
serverCrashFeature UserFeature{..} = (emptyHackageFeature "crash") {
    featureDesc = "Throw various kinds of exceptions (for debugging purposes)"
  , featureResources = [
        (resourceAt "/crash/throw/:userError/:delay") {
          resourceDesc = [ (GET, "Throw a user error") ]
        , resourceGet  = [ ("", throwUserError) ]
        }
      ]
  , featureState = []
  }
  where
    throwUserError :: DynamicPath -> ServerPartE Response
    throwUserError dpath = do
      guardAuthorised_ [InGroup adminGroup]
      liftIO $ do
        let ex :: IOError
            ex = userError $ fromJust (lookup "userError" dpath)

            delay :: Int
            delay = read $ fromJust (lookup "delay" dpath)

        if delay == 0
          then throwIO ex
          else do tid <- myThreadId
                  void . forkIO $ do threadDelay delay
                                     putStrLn "Throwing exception.."
                                     throwTo tid ex
                  return . toResponse $ "Throwing exception in " ++ show delay ++ " microseconds"
