{-# LANGUAGE OverloadedStrings #-}

{-|
Module      : Web.Slack.Auth
Description : Slack Verification
Copyright   : (c) Mo Kweon
Maintainer  : kkweon@gmail.com

This module provides a single function @verify@ which can be used to verify your Slack bot
-}
module Web.Slack.Auth where

import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Crypto.MAC.HMAC (HMAC(HMAC), hmac)
import Data.ByteString (ByteString)
import Data.ByteString.Base16 (decode)
import Data.String (fromString)

import qualified Data.ByteString as B

-- | SlackSigningToken is your Slack Signing Secret
newtype SlackSigningToken =
  SlackSigningToken ByteString
  deriving (Eq, Show)

-- | Timestamp is sent from __X-Slack-Request-Timestamp__ in the request header
newtype Timestamp =
  Timestamp Int
  deriving (Eq, Show, Ord)

-- | Hex is retrieved from __X-Slack-Signature__ in the request header
--
-- Note you don't have to strip "v0=" so you can just pass the header value directly
newtype Hex =
  Hex ByteString
  deriving (Eq, Show)

-- VerificationError occurs when wrong hex is given
newtype VerificationError =
  WrongHex String
  deriving (Eq)

instance Show VerificationError where
  show (WrongHex err) = "[Wrong Hex Code] " ++ err

-- | Verify verifies Slack Request
--
-- Example
--
-- >>> slackSecret = SlackSigningToken "8f742231b10e8888abcd99yyyzzz85a5"
-- >>> timestamp = Timestamp 1531420618
-- >>> body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
-- >>> expectedHash = Hex "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
-- >>> verify slackSecret timestamp body expectedHash
-- Right True
verify ::
     SlackSigningToken -- ^ Slack Token
  -> Timestamp -- ^ X-SlackRequest-Timestamp Header Value
  -> ByteString -- ^ Request body sent by Slack (urlencoded)
  -> Hex -- ^ X-Slack-Signature Header Value (The HMAC will be compared to this value)
  -> Either VerificationError Bool
verify (SlackSigningToken _token) (Timestamp ts) body (Hex _hex) = do
  let sigBaseString =
        fromString "v0:" <> fromString (show ts) <> fromString ":" <> body
  normalizedHex <-
    case B.stripPrefix (fromString "v0=") _hex of
      Just xs -> Right xs
      _ -> Left $ WrongHex ("Unable to strip prefix v0= from " ++ show _hex)
  hexDecoded <-
    case decode normalizedHex of
      (decoded, "") -> Right decoded
      (_, x) -> Left $ WrongHex ("Failed to decode Hex" ++ show x)
  expectedHmac <-
    case digestFromByteString hexDecoded :: Maybe (Digest SHA256) of
      Just digest -> Right (HMAC digest)
      _ -> Left $ WrongHex "Failed to digest from bytestrng"
  return $ hmac _token sigBaseString == expectedHmac
