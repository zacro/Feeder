# Feeder StackWatch

> **This is an unofficial fork of [Feeder](https://github.com/spacecowboy/Feeder) by Jonas Kalderstam (spacecowboy).**
> It is not affiliated with or endorsed by the Feeder project. Please report problems with this fork
> [here](https://github.com/zacro/Feeder/issues), not upstream.

StackWatch is Feeder plus a **Vulnerabilities** tab: tell it which products you run, and it flags
articles from your existing feeds that report security issues in them.

- **My stack:** add products with aliases (e.g. `Jira` / `Atlassian Jira`, `jira-software`) and,
  optionally, the version you run.
- **Alerts:** articles that mention a stack item *and* look security related (CVE ids, "vulnerability",
  "RCE", "actively exploited", …). Matching is case-insensitive on whole words in title and body.
- **Severity & impact:** CVSS score or wording (critical/high/…), CVE ids, exploited-in-the-wild flag,
  and a best-effort "your version looks affected / not affected" check.
- **Notifications** for critical, high and exploited issues (configurable per item), on their own channel.
- **Export/import** of your stack as JSON.

Everything else is Feeder as you know it: offline, no accounts, no Google services. The optional
Sync feature is disabled in this fork.

### Install

- **[Obtainium](https://github.com/ImranR98/Obtainium)** (recommended, gets updates automatically):
  add `https://github.com/zacro/Feeder`.
- Or download the APK from [Releases](https://github.com/zacro/Feeder/releases).

Installs next to the official Feeder (app id `io.github.zacro.stackwatch`). Releases are signed with
the fork's own key, so they can't replace or be replaced by official Feeder builds.

### Building

Same as upstream (see below): `./gradlew assembleFdroidRelease`. Fork changes live on the
`stackwatch` branch; most of the new code is in `app/src/main/java/com/nononsenseapps/feeder/vulns/`.

### License

GPL-3.0, same as Feeder. All credit for the underlying app goes to the Feeder authors and contributors;
consider [supporting the original project](https://ko-fi.com/spacecowboy).

---

*The original Feeder README follows.*

Feeder
=====
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y44OYQL)

<a href="https://f-droid.org/repository/browse/?fdid=com.nononsenseapps.feeder" target="_blank">
<img src="https://f-droid.org/badge/get-it-on.png" alt="Get it on F-Droid" height="80"/></a>

<a href='https://play.google.com/store/apps/details?id=com.nononsenseapps.feeder.play'><img alt='Get it on Google Play' src='https://play.google.com/intl/en_us/badges/static/images/badges/en_badge_web_generic.png' height="80"/></a>

<a href="https://hosted.weblate.org/engage/feeder/">
<img src="https://hosted.weblate.org/widgets/feeder/-/android-strings/svg-badge.svg" alt="Translation status" />
</a>

### Description

Feeder is an open source feed reader (RSS/Atom/JSONFeed) for Android created in 2014.

With Feeder you can read the latest news and posts from your favorite sites.

Feeder does NOT sync with usual remote backends so no account registration of any kind is necessary.

Feeder is free to use and runs locally on your device. Your data is 100% private.

### License

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND**

**GPLv3**, for more info see *LICENSE*.

### Translations are welcome!

If you want to translate Feeder into your native language the easiest way is to go to [Weblate](https://hosted.weblate.org/engage/feeder/) but making a merge request is of course fine if that is something you are comfortable with.

### Quick install

Clone the project:

    git clone https://github.com/spacecowboy/Feeder.git

Then build and install the app to your phone which is connected via USB:

    ./gradlew installFdroidDebug

### Features

* Offline reading
* Notification support
* OPML import/export
* Material Design

### Screenshots

<img src="fastlane/metadata/android/en-US/images/phoneScreenshots/1_en-US_phone_portrait_light_list.png" width=50%/><img src="fastlane/metadata/android/en-US/images/phoneScreenshots/2_en-US_phone_portrait_dark_list.png" width=50%/>
<img src="fastlane/metadata/android/en-US/images/phoneScreenshots/3_en-US_phone_portrait_light_article.png" width=50%/><img src="fastlane/metadata/android/en-US/images/phoneScreenshots/4_en-US_phone_portrait_dark_article.png" width=50%/>
<img src="fastlane/metadata/android/en-US/images/phoneScreenshots/5_en-US_phone_portrait_light_settings.png" width=50%/><img src="fastlane/metadata/android/en-US/images/phoneScreenshots/6_en-US_phone_portrait_dark_settings.png" width=50%/>

### Download

Feeder is available on [F-Droid](https://f-droid.org/en/packages/com.nononsenseapps.feeder/) and [Google Play](https://play.google.com/store/apps/details?id=com.nononsenseapps.feeder.play) and there are APKs available for download on [GitHub Releases](https://github.com/spacecowboy/Feeder/releases).

The GitHub releases are signed with a key matching this signature:

```
SHA-256: C5:EE:FF:22:48:81:35:FF:C2:58:3C:3A:43:B0:53:A1:61:CA:86:98:62:96:1A:B8:53:4F:44:C7:5F:D5:7D:97
```
