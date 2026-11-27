"""Email validation and SMTP-ready verification helpers for NotesAI.

This module is intentionally self-contained. It does not require paid services
or a network call during import. Add ``dnspython`` to requirements to enable
optional MX validation, and set the ``NOTESAI_SMTP_*`` environment variables
when a free SMTP provider is ready.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import smtplib
from email.message import EmailMessage


# Common disposable / temporary email providers. The list is checked against
# the exact domain (and a small suffix match for known disposable subdomains).
DISPOSABLE_DOMAINS = frozenset({
    "0-mail.com", "0clickemail.com", "10minutemail.com", "10minutemail.net",
    "10minutemail.org", "20minutemail.com", "2prong.com", "33mail.com",
    "4warding.com", "4warding.net", "60minutemail.com", "9ox.net",
    "anonbox.net", "anonmails.de", "anonymbox.com", "baxomale.ht.cx",
    "beefmilk.com", "binkmail.com", "bio-muesli.info", "bobmail.info",
    "bofthew.com", "bootybay.de", "boun.cr", "bouncr.com", "breakthru.com",
    "bref.de", "bugmenot.com", "bund.us", "burnthespam.info", "busymail.net",
    "byom.de", "c2.hu", "card.zp.ua", "caveo.de", "chammy.info", "childsavetrust.org",
    "chogmail.com", "clixser.com", "cloudemail.io", "cool.fr.nf", "correo.blogos.net",
    "cosmorph.com", "courriel.fr.nf", "courrieltemporaire.com", "crapmail.org",
    "cubiclink.com", "curryworld.de", "cust.in", "cuvox.de", "d3p.dk",
    "dacoolest.com", "dandikmail.com", "dayrep.com", "deadaddress.com",
    "despam.it", "devnullmail.com", "dfgh.net", "digitalsanctuary.com",
    "dingbone.com", "discard.email", "discardmail.com", "discardmail.de",
    "disposableaddress.com", "disposableemailaddresses.com", "disposableinbox.com",
    "dispose.it", "dispostable.com", "dodgeit.com", "dodgit.com", "donemail.ru",
    "dontreg.com", "dontsendmespam.de", "dump-email.info", "dumpyemail.com",
    "e4ward.com", "easytrashmail.com", "einmalmail.de", "eintagsmail.de",
    "emailgo.de", "emailias.com", "emaillime.com", "emailsensei.com",
    "emailtemporanea.com", "emailtemporanea.net", "emailtemporar.ro",
    "emailtemporario.com.br", "emailthe.net", "emailtmp.com", "emailwarden.com",
    "emailx.at.hm", "emailxfer.com", "emeil.in", "emeil.ir", "emz.net",
    "ero-tube.org", "evopo.com", "explodemail.com", "express.net.ua",
    "eyepaste.com", "fakeinbox.com", "fakeinformation.com", "fansworldwide.de",
    "fantasymail.de", "fastacura.com", "fastchevy.com", "fastchrysler.com",
    "fastkawasaki.com", "fastmazda.com", "fastmitsubishi.com", "fastnissan.com",
    "fastsubaru.com", "fastsuzuki.com", "fasttoyota.com", "fastyamaha.com",
    "filzmail.com", "fivemail.de", "fleckens.hu", "fr33mail.info",
    "frapmail.com", "freundin.ru", "friendlymail.co.uk", "fuckingduh.com",
    "fudgerub.com", "fyii.de", "garliclife.com", "gehensiemirnichtaufdenwecker.net",
    "get1mail.com", "get2mail.fr", "getairmail.com", "getmails.eu",
    "getonemail.com", "getonemail.net", "ghosttexter.de", "giantmail.de",
    "girlsundertheinfluence.com", "gishpuppy.com", "gmial.com", "goemailgo.com",
    "gotmail.net", "gotmail.org", "guerillamail.biz", "guerillamail.com",
    "guerillamail.de", "guerillamail.net", "guerillamail.org", "guerrillamail.biz",
    "guerrillamail.com", "guerrillamail.de", "guerrillamail.net", "guerrillamail.org",
    "guerrillamailblock.com", "gustr.com", "h.mintemail.com", "hacccc.com",
    "haltospam.com", "hatespam.org", "herp.in", "hidemail.de", "hidzz.com",
    "hmamail.com", "hotpop.com", "hulapla.de", "ieatspam.eu", "ieatspam.info",
    "ihateyoualot.info", "iheartspam.org", "imails.info", "inbax.tk",
    "inbox.si", "inboxalias.com", "inboxclean.com", "inboxclean.org",
    "incognitomail.com", "incognitomail.net", "incognitomail.org", "insorg-mail.info",
    "ipoo.org", "irish2me.com", "iwi.net", "jetable.com", "jetable.fr.nf",
    "jetable.net", "jetable.org", "jnxjn.com", "jourrapide.com", "jsrsolutions.com",
    "kaspop.com", "killmail.com", "killmail.net", "kir.ch.tc", "klassmaster.com",
    "klassmaster.net", "klzlk.com", "koszmail.pl", "kurzepost.de", "lawlita.com",
    "letthemeatspam.com", "lhsdv.com", "lifebyfood.com", "link2mail.net",
    "litedrop.com", "lol.ovpn.to", "lolfreak.net", "lookugly.com", "lopl.co.cc",
    "lortemail.dk", "lr78.com", "lroid.com", "lukop.dk", "m21.cc",
    "m4ilweb.info", "maboard.com", "mail-temporaire.fr", "mail.by",
    "mail.mezimages.net", "mail2rss.org", "mail333.com", "mailbidon.com",
    "mailblocks.com", "mailbucket.org", "mailcat.biz", "mailcatch.com",
    "mailde.de", "mailde.info", "maildrop.cc", "maileimer.de", "mailfa.tk",
    "mailforspam.com", "mailfreeonline.com", "mailguard.me", "mailimate.com",
    "mailin8r.com", "mailinater.com", "mailinator.com", "mailinator.net",
    "mailinator.org", "mailinator2.com", "mailincubator.com", "mailismagic.com",
    "mailme.lv", "mailme24.com", "mailmetrash.com", "mailmoat.com",
    "mailms.com", "mailnesia.com", "mailnull.com", "mailorg.org",
    "mailpick.biz", "mailrock.biz", "mailscrap.com", "mailshell.com",
    "mailsiphon.com", "mailtemp.info", "mailtome.de", "mailtothis.com",
    "mailtrash.net", "mailtv.net", "mailtv.tv", "mailzilla.com",
    "makemymail.com", "mansion1.myco.info", "mbx.cc", "mepr.org",
    "mesg.in", "migumail.com", "mintemail.com", "misterpinball.de",
    "moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf", "monumentmail.com",
    "mt2009.com", "mt2014.com", "mycard.net.ua", "mycleaninbox.net",
    "mymail-in.net", "mypacks.net", "mypartyclip.de", "myphantomemail.com",
    "mysamp.de", "mytempemail.com", "mytempmail.com", "mytrashmail.com",
    "nabuma.com", "neomailbox.com", "nepwk.com", "nervmich.net",
    "nervtmich.net", "netmails.com", "netmails.net", "neverbox.com",
    "nice-4u.com", "nincsmail.hu", "nnh.com", "no-spam.ws", "noblepioneer.com",
    "nomail.xl.cx", "nomail2me.com", "nomorespamemails.com", "nospam.ze.tc",
    "nospam4.us", "nospamfor.us", "nospammail.net", "notmailinator.com",
    "nowhere.org", "nowmymail.com", "nurfuerspam.de", "nus.edu.sg",
    "objectmail.com", "obobbo.com", "odnorazovoe.ru", "oneoffemail.com",
    "onewaymail.com", "online.ms", "oopi.org", "opayq.com", "ordinaryamerican.net",
    "otherinbox.com", "ovpn.to", "owlpic.com", "pancakemail.com",
    "pcusers.otherinbox.com", "pjjkp.com", "plexolan.de", "poczta.onet.pl",
    "politikerclub.de", "poofy.org", "pookmail.com", "privacy.net",
    "privatdemail.net", "proxymail.eu", "prtnx.com", "putthisinyourspamdatabase.com",
    "pwrby.com", "quickinbox.com", "rcpt.at", "reallymymail.com",
    "realtyalerts.ca", "recode.me", "recursor.net", "recyclemail.dk",
    "regbypass.com", "regbypass.comsecurenews.com", "rhyta.com",
    "riskfarm.com", "rqa0009.myftp.org", "rubbermail.com", "rubbles.crackers.dk",
    "s.sofort.com", "safersignup.de", "safetymail.info", "safetypost.de",
    "sandelf.de", "saynotospams.com", "schafmail.de", "schrott-email.de",
    "secretemail.de", "selfdestructingmail.com", "sendspamhere.com",
    "senseless-entertainment.com", "services4479.com", "services758.inc",
    "sharedmailbox.org", "sharklasers.com", "shiftmail.com", "shitmail.me",
    "shitware.nl", "shmeriously.com", "shortmail.net", "sibmail.com",
    "sinnlos-mail.de", "siteposting.com", "slaskpost.se", "slopsbox.com",
    "smashmail.de", "smellfear.com", "snakemail.com", "sneakemail.com",
    "sneakmail.de", "snkmail.com", "sofimail.com", "sofort-mail.de",
    "sogetthis.com", "soodonims.com", "spam4.me", "spamail.de",
    "spamarrest.com", "spambob.net", "spambog.com", "spambog.de",
    "spambog.ru", "spambox.info", "spambox.us", "spamcannon.com",
    "spamcannon.net", "spamcon.org", "spamcorptastic.com", "spamcowboy.com",
    "spamcowboy.net", "spamcowboy.org", "spamday.com", "spamex.com",
    "spamfree.eu", "spamfree24.com", "spamfree24.de", "spamfree24.org",
    "spamgoes.in", "spamgourmet.com", "spamgourmet.net", "spamgourmet.org",
    "spamhereplease.com", "spamhole.com", "spamify.com", "spaml.de",
    "spammotel.com", "spamobox.com", "spamslicer.com", "spamspot.com",
    "spamstack.net", "spamthis.co.uk", "spamttr.com", "spamtxt.com",
    "spamvortex.com", "spamwarning.net", "spammy.com", "speed.1s.fr",
    "spl2.de", "spoofmail.de", "squizzy.de", "ssoia.com", "stinkefinger.net",
    "stop-my-spam.com", "stuffmail.de", "super-auswahl.de", "supergreatmail.com",
    "supermailer.jp", "superrito.com", "superstachel.de", "suremail.info",
    "talkinator.com", "teewars.org", "teleworm.com", "teleworm.us",
    "temp-mail.org", "temp-mail.ru", "tempemail.com", "tempemail.net",
    "tempinbox.co.uk", "tempinbox.com", "tempmail.com", "tempmail.eu",
    "tempmail.info", "tempmail.it", "tempmail.net", "tempmail.us",
    "tempmail2.com", "tempmaildemo.com", "tempomail.fr", "temporaryemail.net",
    "temporaryforwarding.com", "temporaryinbox.com", "temporarymailaddress.com",
    "tempthe.net", "thankyou2010.com", "thecloudindex.com", "thisisnotmyrealemail.com",
    "throwawayemailaddress.com", "throwawaymail.com", "tiffi.com", "tinybox.in",
    "tmail.com", "tmailinator.com", "toiea.com", "toomail.biz",
    "topranklist.de", "tradermail.info", "trash-amil.com", "trash-mail.at",
    "trash-mail.com", "trash-mail.de", "trash2009.com", "trashdevil.com",
    "trashemail.de", "trashmail.at", "trashmail.com", "trashmail.de",
    "trashmail.me", "trashmail.net", "trashmail.org", "trashmail.ws",
    "trashmailer.com", "trashymail.com", "trashymail.net", "trillianpro.com",
    "tryalarm.org", "turual.com", "twinmail.de", "tyldd.com", "uggsrock.com",
    "umail.net", "uroid.com", "us.af", "valemail.net", "venompen.com",
    "vergissmail.de", "veryrealemail.com", "viditag.com", "viewcastmedia.com",
    "viewcastmedia.net", "viewcastmedia.org", "viralplays.com", "vpn.st",
    "vsimcard.com", "vubby.com", "wasteland.rfc822.org", "webemail.me",
    "webm4il.info", "weg-werf-email.de", "wegwerf-emails.de", "wegwerfadresse.de",
    "wegwerfemail.com", "wegwerfemail.de", "wegwerfmail.de", "wegwerfmail.info",
    "wegwerfmail.net", "wegwerfmail.org", "wh4f.org", "whyspam.me",
    "willhackforfood.biz", "willselfdestruct.com", "winemaven.info",
    "wronghead.com", "wuzup.net", "wuzupmail.net", "www.e4ward.com",
    "www.mailinator.com", "wwwnew.eu", "x.ip6.li", "xagloo.com",
    "xemaps.com", "xents.com", "xmaily.com", "xoxy.net", "yep.it",
    "yogamaven.com", "yopmail.com", "yopmail.fr", "yopmail.net",
    "yourdomain.com", "yuurok.com", "z1p.biz", "za.com", "zdnn.ru",
    "zippymail.info", "zomg.info", "zxcv.com", "zxcvbnm.com",
})

DISPOSABLE_SUFFIXES = (
    ".tempmail.com", ".mailinator.com", ".yopmail.com", ".trashmail.com",
    ".dispose.it", ".guerillamail.com", ".guerrillamail.com",
)

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def normalize_email(value: str) -> str:
    return str(value or "").strip().lower()


def email_domain(value: str) -> str:
    email = normalize_email(value)
    return email.rsplit("@", 1)[1] if "@" in email else ""


def is_disposable_email(value: str) -> bool:
    domain = email_domain(value)
    if not domain:
        return False
    if domain in DISPOSABLE_DOMAINS:
        return True
    return any(domain.endswith(suffix) for suffix in DISPOSABLE_SUFFIXES)


def has_valid_email_format(value: str) -> bool:
    email = normalize_email(value)
    if len(email) > 254 or ".." in email:
        return False
    return bool(EMAIL_RE.match(email))


def domain_has_mx(domain: str, timeout: float = 2.5) -> bool:
    """Optional MX check. Returns True when DNS is unavailable/unconfigured."""
    if os.getenv("NOTESAI_EMAIL_MX_CHECK", "1").strip().lower() in {"0", "false", "no", "off"}:
        return True
    domain = str(domain or "").strip().rstrip(".").lower()
    if not domain:
        return False
    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore
    except ImportError:
        # Optional dependency: do not block signup when dnspython is absent.
        return True

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        return bool(resolver.resolve(domain, "MX"))
    except (dns.exception.NXDOMAIN, dns.exception.NoAnswer):
        return False
    except Exception:
        # Timeouts / no nameservers are infrastructure problems, not proof that
        # the domain is fake. Fail open so real users are not locked out.
        return True


def validate_real_email(value: str, check_mx: bool = True):
    """Return (is_valid, error_message)."""
    email = normalize_email(value)
    if not has_valid_email_format(email):
        return False, "Enter a valid email address."
    if is_disposable_email(email):
        return False, "Temporary emails are not allowed. Please use a valid email address."
    if check_mx and not domain_has_mx(email_domain(email)):
        return False, "That email domain does not exist. Please use a real email address."
    return True, None


def generate_verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_verification_code(code: str, email: str) -> str:
    return hashlib.sha256((str(code) + "|" + normalize_email(email)).encode("utf-8")).hexdigest()


def smtp_configured() -> bool:
    host = os.getenv("NOTESAI_SMTP_HOST", "").strip()
    sender = os.getenv("NOTESAI_SMTP_FROM", "").strip()
    return bool(host and sender)


def send_verification_email(email: str, code: str) -> tuple[bool, str | None]:
    """Send a 6-digit verification code using SMTP env configuration.

    Required env: NOTESAI_SMTP_HOST, NOTESAI_SMTP_FROM
    Optional env: NOTESAI_SMTP_PORT (587), NOTESAI_SMTP_USER,
                  NOTESAI_SMTP_PASSWORD, NOTESAI_SMTP_STARTTLS (1),
                  NOTESAI_SMTP_SSL (0), NOTESAI_SMTP_TIMEOUT (10)
    """
    if not smtp_configured():
        return False, "SMTP is not configured."

    host = os.getenv("NOTESAI_SMTP_HOST", "").strip()
    port = int(os.getenv("NOTESAI_SMTP_PORT", "587") or 587)
    user = os.getenv("NOTESAI_SMTP_USER", "").strip()
    password = os.getenv("NOTESAI_SMTP_PASSWORD", "")
    sender = os.getenv("NOTESAI_SMTP_FROM", "").strip()
    use_tls = os.getenv("NOTESAI_SMTP_STARTTLS", "1").strip().lower() not in {"0", "false", "no", "off"}
    use_ssl = os.getenv("NOTESAI_SMTP_SSL", "0").strip().lower() in {"1", "true", "yes", "on"}
    timeout = float(os.getenv("NOTESAI_SMTP_TIMEOUT", "10") or 10)

    message = EmailMessage()
    message["Subject"] = "Your NotesAI verification code"
    message["From"] = sender
    message["To"] = normalize_email(email)
    message.set_content(
        "Your NotesAI verification code is: " + str(code) + "\n\n"
        "This code expires in 10 minutes. If you did not create a NotesAI account, ignore this email.\n"
    )

    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=timeout)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
        with server:
            if use_tls and not use_ssl:
                server.starttls()
            if user and password:
                server.login(user, password)
            server.send_message(message)
        return True, None
    except Exception:
        return False, "Could not send the verification email. Please retry."
