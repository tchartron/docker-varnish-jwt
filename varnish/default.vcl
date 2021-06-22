vcl 4.0;

import std;
import var;
import cookie;
import digest;
import crypto;
import blob;

acl purgers {
    "localhost";
    "172.18.0.0"/24;
    "192.168.112.0"/24;
}

backend default {
  .host = "app_nginx";
  .port = "8000";
}

sub vcl_init {
  #JWT public key for token validation
  var.set("key", std.fileread("/etc/varnish/jwtRS256.key.pub"));
  std.syslog(9, var.get("key"));
  std.log(var.get("key"));
  # new v = crypto.verifier(sha256, std.getenv("PUBLIC_KEY"));
  new v = crypto.verifier(sha256, var.get("key"));
}

# Respond to incoming requests.
sub vcl_recv {
  # Remove the "Forwarded" HTTP header if exists (security)
  unset req.http.forwarded;

  #bypass cache when no-cache or private header is present
  if (req.http.cache-control ~ "(no-cache|private)" ||
      req.http.pragma ~ "no-cache") {
         return (pass);
  }

  if (req.method == "PURGE") {
    if (!client.ip ~ purgers) {
      return(synth(405,"Not allowed."));
    }
    return (purge);
  }

  #JWT
  #Cookie
  cookie.parse(req.http.cookie);
  if (cookie.isset("jwt_cookie")) {
    var.set("token", cookie.get("jwt_cookie"));
  }
  #Header
  if (req.http.Authorization && req.http.Authorization ~ "Bearer") {
    var.set("token", regsuball(req.http.Authorization, "Bearer ", ""));
  }

  if (var.get("token") == "") {
    return (synth(401, "Please provide a JWT token"));
  }

  set req.http.tmpHeader = regsub(var.get("token"),"([^\.]+)\.[^\.]+\.[^\.]+","\1");
  set req.http.tmpTyp = regsub(digest.base64_decode(req.http.tmpHeader),{"^.*?"typ"\s*:\s*"(\w+)".*?$"},"\1");
  set req.http.tmpAlg = regsub(digest.base64_decode(req.http.tmpHeader),{"^.*?"alg"\s*:\s*"(\w+)".*?$"},"\1");


  if (req.http.tmpTyp != "JWT") {
      return(synth(401, "Invalid JWT Token: Token is not a JWT: " + req.http.tmpHeader));
  }
  if (req.http.tmpAlg != "RS256") {
      return(synth(401, "Invalid JWT Token: Token does not use RS256 hashing"));
  }

  set req.http.tmpPayload = regsub(var.get("token"),"[^\.]+\.([^\.]+)\.[^\.]+$","\1");
  set req.http.tmpRequestSig = regsub(var.get("token"),"^[^\.]+\.[^\.]+\.([^\.]+)$","\1");

  v.reset();  // need this if request restart
  v.update(req.http.tmpHeader + "." + req.http.tmpPayload );

  if (! v.valid( blob.decode(BASE64URLNOPAD, encoded=req.http.tmpRequestSig))) {
      return (synth(401, "Invalid JWT Token: Signature"));
  }

  set req.http.X-Expiration = regsub(digest.base64_decode(req.http.tmpPayload), {"^.*?"exp":([0-9]+).*?$"},"\1");

  if (std.integer(req.http.X-Expiration, 0) <  std.time2integer(now, 0)) {
      return (synth(401, "Invalid JWT Token: Token expired"));
  }

  unset req.http.tmpHeader;
  unset req.http.tmpTyp;
  unset req.http.tmpAlg;
  unset req.http.tmpPayload;
  unset req.http.tmpRequestSig;

  return (hash);




  # if (req.http.cookie) {
  #   std.log("varnish log info cookie:" + cookie.get("jwt_cookie"));
  #   # std.log(cookie.get("jwt_cookie"));
  # }
  # cookie.parse(req.http.cookie);
  # if (cookie.isset("jwt_cookie")) {
  #   # return (synth(403, "Bobby"));
  #   #Extract header data from JWT
  #   var.set("token", cookie.get("jwt_cookie"));
  #   var.set("header", regsub(var.get("token"),"([^\.]+)\.[^\.]+\.[^\.]+","\1"));
  #   var.set("type", regsub(digest.base64url_decode(var.get("header")),{"^.*?"typ"\s*:\s*"(\w+)".*?$"},"\1"));
  #   var.set("algorithm", regsub(digest.base64url_decode(var.get("header")),{"^.*?"alg"\s*:\s*"(\w+)".*?$"},"\1"));

  #   #Don't allow invalid JWT header
  #   if (var.get("type") == "JWT" && var.get("algorithm") == "RS256") {

  #     #Extract signature & payload data from JWT
  #     var.set("rawPayload",regsub(var.get("token"),"[^\.]+\.([^\.]+)\.[^\.]+$","\1"));
  #     var.set("signature",regsub(var.get("token"),"^[^\.]+\.[^\.]+\.([^\.]+)$","\1"));
  #     var.set("currentSignature",digest.base64url_nopad_hex(digest.hmac_sha256(var.get("key"),var.get("header") + "." + var.get("rawPayload"))));
  #     var.set("payload", digest.base64url_decode(var.get("rawPayload")));
  #     var.set("exp",regsub(var.get("payload"),{"^.*?"exp"\s*:\s*([0-9]+).*?$"},"\1"));
  #     var.set("jti",regsub(var.get("payload"),{"^.*?"jti"\s*:\s*"([a-z0-9A-Z_\-]+)".*?$"},"\1"));
  #     # var.set("userId",regsub(var.get("payload"),{"^.*?"uid"\s*:\s*"([0-9]+)".*?$"},"\1"));
  #     var.set("roles",regsub(var.get("payload"),{"^.*?"roles"\s*:\s*"([a-z0-9A-Z_\-, ]+)".*?$"},"\1"));

  #     #Only allow valid userId
  #     # if (var.get("userId") ~ "^\d+$") {
  #       #Don't allow expired JWT
  #       if (std.time(var.get("exp"),now) >= now) {
  #           #SessionId should match JTI value from JWT
  #           if (cookie.get(var.get("sessionCookie")) == var.get("jti")) {
  #               #Don't allow invalid JWT signature
  #               if (var.get("signature") == var.get("currentSignature")) {
  #                   #The sweet spot
  #                   set req.http.X-login="true";
  #               } else {
  #                   std.log("JWT: signature doesn't match. Received: " + var.get("signature") + ", expected: " + var.get("currentSignature"));
  #               }
  #           } else {
  #             std.log("JWT: session cookie doesn't match JTI." + var.get("sessionCookie") + ": " + cookie.get(var.get("sessionCookie")) + ", JTI:" + var.get("jti"));
  #           }
  #       } else {
  #           std.log("JWT: token has expired");
  #       }
  #     # } else {
  #     #   std.log("UserId '"+ var.get("userId") +"', is not numeric");
  #     # }
  #   } else {
  #     std.log("JWT: type is not JWT or algorithm is not RS256");
  #   }
  #   std.log("JWT processing finished. UserId: " + var.get("userId") + ". X-Login: " + req.http.X-login);

  #   return (hash);
  # }

  #Authorization header
  # if (req.http.Authorization && req.http.Authorization ~ "Bearer") {
  #   set req.http.x-token =  regsuball(req.http.Authorization, "Bearer ", "");

  #   # std.syslog(9, req.http.x-token);
  #   # std.log(req.http.x-token);

  #   set req.http.tmpHeader = regsub(req.http.x-token,"([^\.]+)\.[^\.]+\.[^\.]+","\1");
  #   set req.http.tmpTyp = regsub(digest.base64_decode(req.http.tmpHeader),{"^.*?"typ"\s*:\s*"(\w+)".*?$"},"\1");
  #   set req.http.tmpAlg = regsub(digest.base64_decode(req.http.tmpHeader),{"^.*?"alg"\s*:\s*"(\w+)".*?$"},"\1");


  #   if (req.http.tmpTyp != "JWT") {
  #       return(synth(401, "Invalid JWT Token: Token is not a JWT: " + req.http.tmpHeader));
  #   }
  #   if (req.http.tmpAlg != "RS256") {
  #       return(synth(401, "Invalid JWT Token: Token does not use RS256 hashing"));
  #   }

  #   set req.http.tmpPayload = regsub(req.http.x-token,"[^\.]+\.([^\.]+)\.[^\.]+$","\1");
  #   set req.http.tmpRequestSig = regsub(req.http.x-token,"^[^\.]+\.[^\.]+\.([^\.]+)$","\1");

  #   v.reset();  // need this if request restart
  #   v.update(req.http.tmpHeader + "." + req.http.tmpPayload );

  #   if (! v.valid( blob.decode(BASE64URLNOPAD, encoded=req.http.tmpRequestSig))) {
  #       return (synth(401, "Invalid JWT Token: Signature"));
  #   }

  #   set req.http.X-Expiration = regsub(digest.base64_decode(req.http.tmpPayload), {"^.*?"exp":([0-9]+).*?$"},"\1");

  #   if (std.integer(req.http.X-Expiration, 0) <  std.time2integer(now, 0)) {
  #       return (synth(401, "Invalid JWT Token: Token expired"));
  #   }

  #   unset req.http.tmpHeader;
  #   unset req.http.tmpTyp;
  #   unset req.http.tmpAlg;
  #   unset req.http.tmpPayload;
  #   unset req.http.tmpRequestSig;

  #   return (hash);
  # }
  # return (synth(401, "Please provide a JWT token"));
}
