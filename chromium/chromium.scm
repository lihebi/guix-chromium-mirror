;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016, 2017, 2018 Marius Bakke <mbakke@fastmail.com>
;;;
;;; GNU Guix is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 3 of the License, or (at
;;; your option) any later version.
;;;
;;; GNU Guix is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (chromium chromium)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages assembly)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages build-tools)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gnuzilla)
  #:use-module (gnu packages gperf)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages kerberos)
  #:use-module (gnu packages ninja)
  #:use-module (gnu packages node)
  #:use-module (gnu packages pciutils)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages python-web)
  #:use-module (gnu packages regex)
  #:use-module (gnu packages serialization)
  #:use-module (gnu packages speech)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages valgrind)
  #:use-module (gnu packages vulkan)
  #:use-module (gnu packages video)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg))

(define (chromium-patch-file-name pathspec)
  (let ((patch-name (basename pathspec)))
    (if (string-prefix? "chromium-" patch-name)
        patch-name
        (string-append "chromium-" patch-name))))

;; https://salsa.debian.org/chromium-team/chromium/tree/master/debian/patches
(define (debian-patch pathspec revision hash)
  (origin
    (method url-fetch)
    (uri (string-append
          "https://salsa.debian.org/chromium-team/chromium/raw/"
          revision "/debian/patches/" pathspec))
    (sha256 (base32 hash))
    (file-name (chromium-patch-file-name pathspec))))

;; https://gitweb.gentoo.org/repo/gentoo.git/tree/www-client/chromium/files
(define (gentoo-patch pathspec revision hash)
  (origin
    (method url-fetch)
    (uri (string-append
          "https://gitweb.gentoo.org/repo/gentoo.git/plain/www-client"
          "/chromium/files/" pathspec "?id=" revision))
    (sha256 (base32 hash))
    (file-name (chromium-patch-file-name pathspec))))

;; https://github.com/gcarq/inox-patchset
;; Note: These are now maintained within the ungoogled repository.
(define (inox-patch pathspec revision hash)
  (origin
    (method url-fetch)
    (uri (string-append "https://raw.githubusercontent.com/Eloston"
                        "/ungoogled-chromium/" revision "/patches"
                        "/inox-patchset/" pathspec))
    (sha256 (base32 hash))
    (file-name (chromium-patch-file-name pathspec))))

;; https://github.com/Eloston/ungoogled-chromium
(define (ungoogled-patch pathspec revision hash)
  (origin
    (method url-fetch)
    (uri (string-append "https://raw.githubusercontent.com/Eloston"
                        "/ungoogled-chromium/" revision "/patches"
                        "/ungoogled-chromium/" pathspec))
    (sha256 (base32 hash))
    (file-name (chromium-patch-file-name pathspec))))

;; https://git.archlinux.org/svntogit/packages.git/tree/trunk?h=packages/chromium
(define (arch-patch pathspec revision hash)
  (origin
    (method url-fetch)
    (uri (string-append "https://git.archlinux.org/svntogit/packages.git"
                        "/plain/trunk/" pathspec "?h=packages/chromium"
                        "&id=" revision))
    (sha256
     (base32
      "1x8sy7m9qw7z9f85af40czj4vwjx2vlc403gh2w04k03v6zd3wn4"))
    (file-name (chromium-patch-file-name pathspec))))

(define %debian-revision "debian/70.0.3538.67-1")
(define %ungoogled-revision "be93ead958dea4c7b03446c5935542019f0d2ae1")
(define %inox-revision %ungoogled-revision)
(define %arch-revision "3a387aa30dbbe7bf3b5f00b1d1497d93d1b0c52a")

(define %debian-patches
  (list
   ;; GCC does not support initializer list member assignment.
   (debian-patch "fixes/member-assignment.patch" %debian-revision
                 "0dqz2nlvdszpjb9bbz9vqkvzwar1hncdqksgkydvzwlpjvz8g1yx")
   ;; Help GCC resolve some classes in a jumbo configuration.
   (debian-patch "fixes/namespace.patch" %debian-revision
                 "1jf3cbkq1wdh3c8dwz7xlf661j73ma4k3cil71wsjfnqrjj8hr6h")
   ;; Add constexpr on methods where it is required.
   (debian-patch "fixes/constexpr.patch" %debian-revision
                 "0kw88wrcr7g69msdlr5k3jwwfq8pvdvr1p2nyxqpxn2kwhhwb5zf")
   ;; Avoid dependency on NSPR when bootstrapping the build tools.
   (debian-patch "system/nspr.patch" %debian-revision
                 "0n0hxmxnn033wlzijb9749dc6a4mvkhq5p7gvr4hcwh1in0k3hnn")
   ;; Ditto for system libevent.
   (debian-patch "system/event.patch" %debian-revision
                 "1m9wzcs49h0n78rn3lbqgdh1wh62bqsfp30kqd8rphx6lmbw2mar")
   ;; Make PDFium use system OpenJPEG.
   (debian-patch "system/openjpeg.patch" %debian-revision
                 "185y9zssllfdib7qknnx1vgrj5iqjrqljpib49bazd5ssl3zn767")
   ;; Make "Courgette" use system zlib instead of the bundled lzma.
   (debian-patch "system/zlib.patch" %debian-revision
                 "1fmkiw7xrhwadvjxkzpv8j5iih2ws59l3llsdrpapw1vybfyq9nr")
   ;; Avoid dependency on Android tools.
   (debian-patch "disable/android.patch" %debian-revision
                 "1drmy7izyl2lg7fjm9xnvnm17i7xn5269q95l433m1g6jmy7w6zh")
   ;; Do not show a warning about missing API keys.
   (debian-patch "disable/google-api-warning.patch" %debian-revision
                 "0h311w19y7qnm1vg1jpdb4mqw6dwvl1i2yw9dm6xm0qkl76k5qwg")
   ;; Don't override the home page set in master_preferences.
   (debian-patch "disable/welcome-page.patch" %debian-revision
                 "0cj6g9yy02nd2s7wlyp1rdyy7ykg6zdkbzh8ralr7gpgbwzjb999")
   ;; Fix alignof() usage with GCC8; upstream wants __alignof__.
   (debian-patch "fixes/alignof.patch" %debian-revision
                 "0dkddi7l9r1hjylypcndnrvjx296si5apc3n92kcl5l7mc5gfdfb")))

(define %inox-patches
  (list
   ;; Fix build without the "safe browsing" feature.
   (inox-patch "0001-fix-building-without-safebrowsing.patch" %inox-revision
               "0avkhb5fpk4zbbk1sjmsylqn7kccdznc5fh90svi3s8phxvy519g")
   ;; Use sane defaults.  In particular, don't depend on any Google services.
   (inox-patch "0006-modify-default-prefs.patch" %inox-revision
               "0vjljwfl0qlcdkvh4k18vaqpx14b6jnlfdkcdbskgn13cps1v6fq")
   ;; Recent versions of Chromium may load a remote search engine on the "New
   ;; Tab Page", which causes unnecessary and involuntary network traffic.
   (inox-patch "0008-restore-classic-ntp.patch" %inox-revision
               "1paghqp3viaq03618rhppf2xki1k2s1x3lh3h218yy3zvk34wshx")
   ;; Add DuckDuckGo and use it as the default search engine.
   (inox-patch "0011-add-duckduckgo-search-engine.patch" %inox-revision
               "0mvw1ax0gw3d252c9b1pwbk0j7ny8z9nsfywcmhj56wm6yksgpkg")
   ;; Don't fetch translation packs when opening settings for the first time.
   (inox-patch "0014-disable-translation-lang-fetch.patch" %inox-revision
               "0lbmcjfxx2rz3daqbhd3cizpynjk2klmsjh1qd7ryhnkfs7ngywx")
   ;; Don't start a "Login Wizard" at first launch.
   (inox-patch "0018-disable-first-run-behaviour.patch" %inox-revision
               "1idp1l37l9bzwi8wabj7gi614zi845fpagj9cpddicrvjg169kbq")))

(define %ungoogled-patches
  (list
   ;; Disable browser sign-in to prevent leaking data at launch.
   (ungoogled-patch "disable-signin.patch" %ungoogled-revision
                    "0y32cqg23mxari0y20d4j3qmn903yxzw5swv9pjh9sjzilg1q5ld")
   ;; Don't report back to servers with information about errors.
   (ungoogled-patch "disable-domain-reliability.patch" %ungoogled-revision
                    "1wsvxbbgyb8gsi7c7kxwk8s4kwkrp3rm66kjhbyylkis1p4pgmvc")))

(define %arch-patches
  (list
   (arch-patch "chromium-system-icu.patch" %arch-revision
               "1x8sy7m9qw7z9f85af40czj4vwjx2vlc403gh2w04k03v6zd3wn4")))

(define opus+custom
  (package (inherit opus)
           (name "opus+custom")
           (arguments
            (substitute-keyword-arguments (package-arguments opus)
              ((#:configure-flags flags ''())
               ;; Opus Custom is an optional extension of the Opus
               ;; specification that allows for unsupported frame
               ;; sizes.  Chromium requires that this is enabled.
               `(cons "--enable-custom-modes"
                      ,flags))))))

(define libvpx/chromium
  ;; Chromium 66 and later requires an unreleased libvpx, so we take the
  ;; commit from "third_party/libvpx/README.chromium" in the tarball.
  (let ((version (package-version libvpx))
        (commit "753fd86e86ac727dccac88376260b8f54502f2a3")
        (revision "0"))
    (package
      (inherit libvpx)
      (name "libvpx-chromium")
      (version (git-version version revision commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://chromium.googlesource.com/webm/libvpx")
                      (commit commit)))
                (file-name (git-file-name name version))
                (sha256
                 (base32
                  "0i4xbif70gasljsmxnsvw4dxx9hwf94kz3s12ki062n6c0b41mb7")))))))

(define-public gn
  (let ((commit "77d64a3da6bc7d8b0aab83ff7459b3280e6a84f2")
        (revision "1469"))          ;as returned by `git describe`, used below
    (package
      (name "gn")
      (version (git-version "0.0" revision commit))
      (home-page "https://gn.googlesource.com/gn")
      (source (origin
                (method git-fetch)
                (uri (git-reference (url home-page) (commit commit)))
                (sha256
                 (base32
                  "0mgf2w4rz7y7fdx553wv3r3f49s4c5r8vykp0y6w75rrdyd2p7va"))
                (file-name (git-file-name name version))))
      (build-system gnu-build-system)
      (arguments
       `(#:tests? #f                    ;XXX tests aren't built
         #:phases (modify-phases %standard-phases
                    (add-before 'configure 'set-build-environment
                      (lambda _
                        (setenv "CC" "gcc") (setenv "CXX" "g++")
                        (setenv "AR" "ar")
                        #t))
                    (replace 'configure
                      (lambda _
                        (invoke "python" "build/gen.py" "--no-sysroot"
                                "--no-last-commit-position")))
                    (add-after 'configure 'create-last-commit-position
                      (lambda _
                        ;; Create "last_commit_position.h" to avoid a dependency
                        ;; on 'git' (and the checkout..).
                        (call-with-output-file "out/last_commit_position.h"
                          (lambda (port)
                            (format port
                                    "#define LAST_COMMIT_POSITION \"~a (~a)\"\n"
                                    ,revision ,(string-take commit 8))
                            #t))))
                    (replace 'build
                      (lambda _
                        (invoke "ninja" "-C" "out" "gn"
                                "-j" (number->string (parallel-job-count)))))
                    (replace 'install
                      (lambda* (#:key outputs #:allow-other-keys)
                        (let ((out (assoc-ref outputs "out")))
                          (install-file "out/gn" (string-append out "/bin"))
                          #t))))))
      (native-inputs
       `(("ninja" ,ninja)
         ("python" ,python-2)))
      (synopsis "Generate Ninja build files")
      (description
       "GN is a tool that collects information about a project from
@file{.gn} files and generates build files for the Ninja build system.")
      ;; GN is distributed as BSD-3, but bundles a couple of files
      ;; from ICU using the X11 license.
      (license (list license:bsd-3 license:x11)))))

(define-public chromium
  (package
    (name "chromium")
    (version "70.0.3538.67")
    (synopsis "Graphical web browser")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://commondatastorage.googleapis.com"
                                  "/chromium-browser-official/chromium-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "0dqfwghl73gcmbnl9wb3i5wz8q65y1vhg7n0m2nh0hv33w1w4mp9"))
              (patches (append %debian-patches
                               %inox-patches
                               %ungoogled-patches
                               %arch-patches
                               (search-patches
                                "chromium/patches/chromium-remove-default-history.patch")))
              (modules '((srfi srfi-1)
                         (srfi srfi-26)
                         (ice-9 ftw)
                         (ice-9 match)
                         (ice-9 regex)
                         (guix build utils)))
              (snippet
               '(begin
                  (let ((preserved-club
                         (map
                          (lambda (path)
                            ;; Prepend paths with "./" for comparison with ftw.
                            (string-append "./" path))
                          (list
                           "base/third_party/dmg_fp" ;ISC/X11-like
                           "base/third_party/dynamic_annotations" ;BSD-2
                           "base/third_party/icu" ;X11-like
                           "base/third_party/superfasthash" ;BSD-3
                           "base/third_party/symbolize" ;BSD-3
                           "base/third_party/xdg_mime" ;ASL-2.0
                           "base/third_party/xdg_user_dirs" ;Expat
                           "chrome/third_party/mozilla_security_manager" ;MPL-1.1
                           "courgette/third_party/bsdiff" ;BSD protection license
                           "courgette/third_party/divsufsort" ;Expat
                           "net/third_party/http2" ;BSD-3
                           "net/third_party/mozilla_security_manager" ;MPL-1.1
                           "net/third_party/nss" ;MPL-2.0
                           "net/third_party/quic" ;BSD-3
                           "net/third_party/spdy" ;BSD-3
                           "net/third_party/uri_template" ;ASL2.0
                           "third_party/abseil-cpp" ;ASL2.0
                           "third_party/adobe/flash/flapper_version.h" ;no license, trivial
                           ;; FIXME: This is used in:
                           ;; * ui/webui/resources/js/analytics.js
                           ;; * ui/file_manager/
                           "third_party/analytics" ;ASL2.0
                           "third_party/angle" ;BSD-3
                           "third_party/angle/src/common/third_party/base" ;BSD-3
                           "third_party/angle/src/common/third_party/smhasher" ;Public domain
                           "third_party/angle/src/third_party/compiler" ;BSD-2
                           "third_party/angle/src/third_party/libXNVCtrl" ;Expat
                           "third_party/angle/src/third_party/trace_event" ;BSD-3
                           "third_party/angle/third_party/glslang" ;BSD-3
                           "third_party/angle/third_party/spirv-headers" ;Expat
                           "third_party/angle/third_party/spirv-tools" ;Expat
                           "third_party/angle/third_party/vulkan-headers" ;ASL2.0
                           "third_party/angle/third_party/vulkan-loader" ;ASL2.0
                           "third_party/angle/third_party/vulkan-tools" ;ASL2.0
                           "third_party/angle/third_party/vulkan-validation-layers" ;ASL2.0
                           "third_party/apple_apsl" ;APSL2.0
                           "third_party/blink" ;BSD-3
                           "third_party/boringssl" ;OpenSSL/ISC (Google additions are ISC)
                           "third_party/boringssl/src/third_party/fiat" ;Expat
                           "third_party/breakpad" ;BSD-3
                           "third_party/brotli" ;Expat
                           "third_party/cacheinvalidation" ;ASL2.0
                           "third_party/catapult" ;BSD-3
                           "third_party/catapult/common/py_vulcanize/third_party/rcssmin" ;ASL2.0
                           "third_party/catapult/common/py_vulcanize/third_party/rjsmin" ;ASL2.0
                           "third_party/catapult/third_party/polymer" ;BSD-3
                           "third_party/catapult/tracing/third_party/d3" ;BSD-3
                           "third_party/catapult/tracing/third_party/gl-matrix" ;Expat
                           "third_party/catapult/tracing/third_party/jszip" ;Expat or GPL3
                           "third_party/catapult/tracing/third_party/mannwhitneyu" ;Expat
                           "third_party/catapult/tracing/third_party/oboe" ;BSD-2
                           "third_party/catapult/tracing/third_party/pako" ;Expat
                           "third_party/ced" ;BSD-3
                           "third_party/cld_3" ;ASL2.0
                           "third_party/crashpad" ;ASL2.0
                           (string-append "third_party/crashpad/crashpad/"
                                          "third_party/zlib/zlib_crashpad.h") ;Zlib
                           "third_party/crc32c" ;BSD-3
                           "third_party/cros_system_api" ;BSD-3
                           "third_party/dom_distiller_js" ;BSD-3
                           "third_party/fips181" ;BSD-3
                           "third_party/flatbuffers" ;ASL2.0
                           "third_party/google_input_tools" ;ASL2.0
                           "third_party/google_input_tools/third_party/closure_library" ;ASL2.0
                           (string-append "third_party/google_input_tools/third_party"
                                          "/closure_library/third_party/closure") ;Expat
                           "third_party/googletest" ;BSD-3
                           "third_party/hunspell" ;MPL1.1
                           "third_party/iccjpeg" ;IJG
                           "third_party/inspector_protocol" ;BSD-3
                           "third_party/jinja2" ;BSD-3
                           "third_party/jstemplate" ;ASL2.0
                           "third_party/khronos" ;Expat, SGI
                           "third_party/leveldatabase" ;BSD-3
                           "third_party/libXNVCtrl" ;Expat
                           "third_party/libaddressinput" ;ASL2.0
                           "third_party/libaom" ;BSD-2
                           "third_party/libaom/source/libaom/third_party/vector" ;Expat
                           "third_party/libaom/source/libaom/third_party/x86inc" ;ISC
                           "third_party/libjingle_xmpp" ;BSD-3
                           "third_party/libphonenumber" ;ASL2.0
                           ;; FIXME: Needs pkg-config support.
                           "third_party/libsecret" ;LGPL2.1+
                           "third_party/libsrtp" ;BSD-3
                           ;; TODO: Package this and purge.
                           "third_party/libsync" ;ASL2.0
                           "third_party/libudev" ;LGPL2.1+
                           "third_party/libwebm" ;BSD-3
                           "third_party/libxml" ;X11
                           "third_party/libyuv" ;BSD-3
                           "third_party/lss" ;BSD-3
                           "third_party/markupsafe" ;BSD-3
                           "third_party/mesa_headers" ;X11
                           "third_party/metrics_proto" ;BSD-3
                           "third_party/modp_b64" ;BSD-3
                           "third_party/node" ;Expat
                           (string-append "third_party/node/node_modules/"
                                          "polymer-bundler/lib/third_party/UglifyJS2") ;BSD-2
                           "third_party/ots" ;BSD-3
                           ;; TODO: Build as extension.
                           "third_party/pdfium" ;BSD-3
                           "third_party/pdfium/third_party/agg23" ;Expat
                           "third_party/pdfium/third_party/base" ;BSD-3
                           "third_party/pdfium/third_party/bigint" ;Public domain
                           "third_party/pdfium/third_party/skia_shared" ;BSD-3
                           (string-append "third_party/pdfium/third_party/freetype"
                                          "/include/pstables.h") ;FreeType
                           "third_party/perfetto" ;ASL2.0
                           "third_party/ply" ;BSD-3
                           "third_party/polymer" ;BSD-3
                           "third_party/protobuf" ;BSD-3
                           "third_party/protobuf/third_party/six" ;Expat
                           "third_party/pyjson5" ;ASL2.0
                           "third_party/qcms" ;Expat
                           "third_party/rnnoise" ;BSD-3
                           "third_party/sfntly" ;ASL2.0
                           "third_party/skia" ;BSD-3
                           "third_party/skia/third_party/skcms" ;BSD-3
                           "third_party/skia/third_party/vulkan" ;BSD-3
                           "third_party/skia/third_party/vulkanmemoryallocator" ;BSD-3
                           "third_party/skia/third_party/gif" ;MPL1.1
                           "third_party/smhasher" ;Expat
                           "third_party/speech-dispatcher" ;GPL2+
                           "third_party/sqlite" ;Public domain
                           "third_party/swiftshader" ;ASL2.0
                           "third_party/swiftshader/third_party/llvm-subzero" ;NCSA
                           "third_party/swiftshader/third_party/subzero" ;NCSA
                           "third_party/s2cellid" ;ASL2.0
                           "third_party/usb_ids" ;BSD-3
                           "third_party/usrsctp" ;BSD-2
                           "third_party/WebKit" ;BSD-2 or BSD-3
                           "third_party/web-animations-js" ;ASL2.0
                           "third_party/webdriver" ;ASL2.0
                           "third_party/webrtc" ;BSD-3
                           "third_party/webrtc/common_audio/third_party/fft4g" ;Custom
                           "third_party/webrtc/common_audio/third_party/spl_sqrt_floor" ;Public domain
                           "third_party/webrtc/modules/third_party/fft" ;Custom
                           "third_party/webrtc/modules/third_party/g711" ;Public domain
                           "third_party/webrtc/modules/third_party/g722" ;Public domain
                           "third_party/webrtc/rtc_base/third_party/base64" ;Custom
                           "third_party/webrtc/rtc_base/third_party/sigslot" ;Public domain
                           "third_party/webrtc_overrides" ;BSD-3
                           "third_party/widevine/cdm/widevine_cdm_version.h" ;BSD-3
                           "third_party/widevine/cdm/widevine_cdm_common.h" ;BSD-3
                           "third_party/woff2" ;ASL2.0
                           "third_party/xdg-utils" ;Expat
                           "third_party/yasm/run_yasm.py" ;BSD-2 or BSD-3
                           "third_party/zlib/google" ;BSD-3
                           "url/third_party/mozilla" ;BSD-3, part MPL1.1
                           "v8/src/third_party/utf8-decoder" ;Expat
                           "v8/src/third_party/valgrind" ;BSD-4
                           "v8/third_party/v8/builtins" ;PSFL
                           "v8/third_party/inspector_protocol")))) ;BSD-3

                    (define (empty? dir)
                      (equal? (scandir dir) '("." "..")))

                    (define (third-party? file)
                      (if (string-contains file "third_party/")
                          #t
                          #f))

                    (define (useless? file)
                      (any (cute string-suffix? <> file)
                           '(".tar.gz" ".zip" ".exe" ".jar")))

                    (define (parents child)
                      (let ((lst (reverse (string-split child #\/))))
                        (let loop ((hierarchy lst)
                                   (result '()))
                          (if (or (null? hierarchy)
                                  (and (not (null? result))
                                       (string-suffix? "third_party" (car result))))
                              result
                              (loop (cdr hierarchy)
                                    (cons (string-join (reverse hierarchy) "/")
                                          result))))))

                    (define (delete-unwanted-files child stat flag base level)
                      (let ((protected (make-regexp "\\.(gn|gyp)i?$")))
                        (match flag
                          ((or 'regular 'symlink 'stale-symlink)
                           (when (third-party? child)
                             (unless (or (member child preserved-club)
                                         (any (cute member <> preserved-club)
                                              (parents child))
                                         (regexp-exec protected child))
                               (format (current-error-port) "deleting ~s~%" child)
                               (delete-file child)))
                           (when (and (useless? child) (file-exists? child))
                             (delete-file child))
                           #t)
                          ('directory-processed
                           (when (empty? child)
                             (rmdir child))
                           #t)
                          (_ #t))))

                    (nftw "." delete-unwanted-files 'depth 'physical)

                    ;; Assert that each listed item is present to catch removals.
                    (for-each (lambda (third-party)
                                (unless (file-exists? third-party)
                                  (error (format #f "~s does not exist!" third-party))))
                              preserved-club)

                    ;; Replace "GN" files from third_party with shims for
                    ;; building against system libraries.  Keep this list in
                    ;; sync with "build/linux/unbundle/replace_gn_files.py".
                    (for-each (lambda (pair)
                                (let ((source (string-append
                                               "build/linux/unbundle/" (car pair)))
                                      (dest (cdr pair)))
                                  (copy-file source dest)))
                              (list
                               '("ffmpeg.gn" . "third_party/ffmpeg/BUILD.gn")
                               '("flac.gn" . "third_party/flac/BUILD.gn")
                               '("fontconfig.gn" . "third_party/fontconfig/BUILD.gn")
                               '("freetype.gn" . "build/config/freetype/freetype.gni")
                               '("harfbuzz-ng.gn" .
                                 "third_party/harfbuzz-ng/harfbuzz.gni")
                               '("icu.gn" . "third_party/icu/BUILD.gn")
                               '("libdrm.gn" . "third_party/libdrm/BUILD.gn")
                               '("libevent.gn" . "base/third_party/libevent/BUILD.gn")
                               '("libjpeg.gn" . "third_party/libjpeg.gni")
                               '("libpng.gn" . "third_party/libpng/BUILD.gn")
                               '("libvpx.gn" . "third_party/libvpx/BUILD.gn")
                               '("libwebp.gn" . "third_party/libwebp/BUILD.gn")
                               '("libxml.gn" . "third_party/libxml/BUILD.gn")
                               '("libxslt.gn" . "third_party/libxslt/BUILD.gn")
                               '("openh264.gn" . "third_party/openh264/BUILD.gn")
                               '("opus.gn" . "third_party/opus/BUILD.gn")
                               '("re2.gn" . "third_party/re2/BUILD.gn")
                               '("snappy.gn" . "third_party/snappy/BUILD.gn")
                               '("yasm.gn" . "third_party/yasm/yasm_assemble.gni")
                               '("zlib.gn" . "third_party/zlib/BUILD.gn")))
                    #t)))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f
       ;; FIXME: There is a "gn" option specifically for setting -rpath, but
       ;; it overrides the RUNPATH set by the linker.
       #:validate-runpath? #f
       #:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (ice-9 ftw)
                  (ice-9 regex)
                  (srfi srfi-26))
       #:configure-flags
       ;; See tools/gn/docs/cookbook.md and
       ;; https://www.chromium.org/developers/gn-build-configuration
       ;; for usage.  Run "./gn args . --list" in the Release
       ;; directory for an exhaustive list of supported flags.
       ;; (Note: The 'configure' phase will do that for you.)
       (list "is_debug=false"
             "use_gold=false"
             "use_lld=false"
             "linux_use_bundled_binutils=false"
             "use_custom_libcxx=false"
             "use_sysroot=false"
             "enable_precompiled_headers=false"
             "goma_dir=\"\""
             "enable_nacl=false"
             "enable_nacl_nonsfi=false"
             "use_allocator=\"none\""   ;don't use tcmalloc
             "use_unofficial_version_number=false"

             ;; Disable "safe browsing", which pulls in a dependency on
             ;; the nonfree "unrar" program (as of m66).
             "safe_browsing_mode=0"

             ;; Define a custom toolchain that simply looks up CC, AR and
             ;; friends from the environment.
             "custom_toolchain=\"//build/toolchain/linux/unbundle:default\""
             "host_toolchain=\"//build/toolchain/linux/unbundle:default\""

             ;; Don't assume it's clang.
             "is_clang=false"

             ;; Optimize for building everything at once, as opposed to
             ;; incrementally for development.  See "docs/jumbo.md".
             "use_jumbo_build=true"

             ;; Disable debugging features to save space.
             "symbol_level=0"
             "remove_webcore_debug_symbols=true"
             "enable_iterator_debugging=false"

             ;; Some of the unbundled libraries throws deprecation
             ;; warnings, etc.  Ignore it.
             "treat_warnings_as_errors=false"

             ;; Don't add any API keys.  End users can set them in the
             ;; environment if desired.  See
             ;; <https://www.chromium.org/developers/how-tos/api-keys>.
             "use_official_google_api_keys=false"

             ;; Disable "field trials".
             "fieldtrial_testing_like_official_build=true"

             ;; Disable Chrome Remote Desktop (aka Chromoting).
             "enable_remoting=false"

             ;; Use system libraries where possible.
             "use_system_freetype=true"
             "use_system_harfbuzz=true"
             "use_system_lcms2=true"
             "use_system_libjpeg=true"
             "use_system_libpng=true"
             "use_system_zlib=true"

             "use_gnome_keyring=false"  ;deprecated by libsecret
             "use_openh264=true"
             "use_xkbcommon=true"
             "use_pulseaudio=true"
             "link_pulseaudio=true"

             ;; Don't arbitrarily restrict formats supported by system ffmpeg.
             "proprietary_codecs=true"
             "ffmpeg_branding=\"Chrome\""

             ;; WebRTC stuff.
             "rtc_use_h264=true"
             ;; Don't use bundled sources.
             "rtc_build_json=false"
             "rtc_build_libevent=false"
             "rtc_build_libvpx=false"
             "rtc_build_opus=false"
             "rtc_build_ssl=false"

             "rtc_build_libsrtp=true"   ;FIXME: fails to find headers
             "rtc_build_usrsctp=true"   ;TODO: package this
             (string-append "rtc_jsoncpp_root=\""
                            (assoc-ref %build-inputs "jsoncpp")
                            "/include/jsoncpp/json\"")
             (string-append "rtc_ssl_root=\""
                            (assoc-ref %build-inputs "openssl")
                            "/include/openssl\""))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-stuff
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "printing/cups_config_helper.py"
               (("cups_config =.*")
                (string-append "cups_config = '" (assoc-ref inputs "cups")
                               "/bin/cups-config'\n")))

             (substitute*
                 '("base/process/launch_posix.cc"
                   "base/third_party/dynamic_annotations/dynamic_annotations.c"
                   "sandbox/linux/seccomp-bpf/sandbox_bpf.cc"
                   "sandbox/linux/services/credentials.cc"
                   "sandbox/linux/services/namespace_utils.cc"
                   "sandbox/linux/services/syscall_wrappers.cc"
                   "sandbox/linux/syscall_broker/broker_host.cc")
               (("include \"base/third_party/valgrind/") "include \"valgrind/"))

             (for-each (lambda (file)
                         (substitute* file
                           ;; Fix opus include path.
                           ;; Do not substitute opus_private.h.
                           (("#include \"opus\\.h\"")
                            "#include \"opus/opus.h\"")
                           (("#include \"opus_custom\\.h\"")
                            "#include \"opus/opus_custom.h\"")
                           (("#include \"opus_defines\\.h\"")
                            "#include \"opus/opus_defines.h\"")
                           (("#include \"opus_multistream\\.h\"")
                            "#include \"opus/opus_multistream.h\"")
                           (("#include \"opus_types\\.h\"")
                            "#include \"opus/opus_types.h\"")))
                       (find-files (string-append "third_party/webrtc/modules"
                                                  "/audio_coding/codecs/opus")))

             (substitute* "chrome/common/chrome_paths.cc"
               (("/usr/share/chromium/extensions")
                ;; TODO: Add ~/.guix-profile.
                "/run/current-system/profile/share/chromium/extensions"))

             (substitute*
                 "third_party/breakpad/breakpad/src/common/linux/libcurl_wrapper.h"
               (("include \"third_party/curl") "include \"curl"))

             (substitute* "media/base/decode_capabilities.cc"
               (("third_party/libvpx/source/libvpx/") ""))

             (substitute* "ui/gfx/skia_util.h"
               (("third_party/vulkan/include/") ""))

             ;; Building chromedriver embeds some files using the ZIP
             ;; format which doesn't support timestamps before
             ;; 1980. Therefore, advance the timestamps of the files
             ;; which are included so that building chromedriver
             ;; works.
             (let ((circa-1980 (* 10 366 24 60 60)))
               (for-each (lambda (file)
                           (utime file circa-1980 circa-1980))
                         '("chrome/test/chromedriver/extension/background.js"
                           "chrome/test/chromedriver/extension/manifest.json")))

             #t))
         (add-before 'configure 'prepare-build-environment
           (lambda* (#:key inputs #:allow-other-keys)

             ;; Make sure the right build tools are used.
             (setenv "AR" "ar") (setenv "NM" "nm")
             (setenv "CC" "gcc") (setenv "CXX" "g++")

             ;; Work around <https://bugs.gnu.org/30756>.
             (unsetenv "C_INCLUDE_PATH")
             (unsetenv "CPLUS_INCLUDE_PATH")

             ;; TODO: pre-compile instead. Avoids a race condition.
             (setenv "PYTHONDONTWRITEBYTECODE" "1")

             ;; XXX: How portable is this.
             (mkdir-p "third_party/node/linux/node-linux-x64")
             (symlink (string-append (assoc-ref inputs "node") "/bin")
                      "third_party/node/linux/node-linux-x64/bin")

             #t))
         (replace 'configure
           (lambda* (#:key configure-flags #:allow-other-keys)
             (let ((args (string-join configure-flags " ")))
               ;; Generate ninja build files.
               (invoke "gn" "gen" "out/Release"
                       (string-append "--args=" args))

               ;; Print the full list of supported arguments as well as
               ;; their current status for convenience.
               (format #t "Dumping configure flags...\n")
               (invoke "gn" "args" "out/Release" "--list"))))
         (replace 'build
           (lambda* (#:key outputs #:allow-other-keys)
             (invoke "ninja" "-C" "out/Release"
                     "-j" (number->string (parallel-job-count))
                     "chrome"
                     "chromedriver")))
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out            (assoc-ref outputs "out"))
                    (bin            (string-append out "/bin"))
                    (exe            (string-append bin "/chromium"))
                    (lib            (string-append out "/lib"))
                    (man            (string-append out "/share/man/man1"))
                    (applications   (string-append out "/share/applications"))
                    (install-regexp (make-regexp "\\.(bin|pak)$"))
                    (locales        (string-append lib "/locales"))
                    (resources      (string-append lib "/resources"))
                    (preferences    (assoc-ref inputs "master-preferences"))
                    (gtk+           (assoc-ref inputs "gtk+"))
                    (mesa           (assoc-ref inputs "mesa"))
                    (nss            (assoc-ref inputs "nss"))
                    (udev           (assoc-ref inputs "udev"))
                    (sh             (which "sh")))

               (substitute* '("chrome/app/resources/manpage.1.in"
                              "chrome/installer/linux/common/desktop.template")
                 (("@@MENUNAME@@") "Chromium")
                 (("@@PACKAGE@@") "chromium")
                 (("/usr/bin/@@USR_BIN_SYMLINK_NAME@@") exe))

               (mkdir-p man)
               (copy-file "chrome/app/resources/manpage.1.in"
                          (string-append man "/chromium.1"))

               (mkdir-p applications)
               (copy-file "chrome/installer/linux/common/desktop.template"
                          (string-append applications "/chromium.desktop"))

               (mkdir-p lib)
               (copy-file preferences (string-append lib "/master_preferences"))

               (with-directory-excursion "out/Release"
                 (for-each (lambda (file)
                             (install-file file lib))
                           (scandir "." (cut regexp-exec install-regexp <>)))
                 (copy-file "chrome" (string-append lib "/chromium"))

                 ;; TODO: Install icons from "../../chrome/app/themes" into
                 ;; "out/share/icons/hicolor/$size".
                 (install-file
                  "product_logo_48.png"
                  (string-append out "/share/icons/48x48/chromium.png"))

                 (copy-recursively "locales" locales)
                 (copy-recursively "resources" resources)

                 (mkdir-p bin)
                 ;; Add a thin wrapper to prevent the user from inadvertently
                 ;; installing non-free software through the Web Store.
                 ;; TODO: Discover extensions from the profile and pass
                 ;; something like "--disable-extensions-except=...".
                 (call-with-output-file exe
                   (lambda (port)
                     (format port
                             "#!~a~@
                             if [ -z \"$CHROMIUM_ENABLE_WEB_STORE\" ]~@
                             then~@
                               CHROMIUM_FLAGS=\" \\~@
                                 --disable-background-networking \\~@
                                 --disable-extensions \\~@
                               \"~@
                             fi~@
                             exec ~a $CHROMIUM_FLAGS \"$@\"~%"
                             sh (string-append lib "/chromium"))))
                 (chmod exe #o755)
                 (install-file "chromedriver" bin)

                 (wrap-program exe
                   ;; TODO: Get these in RUNPATH.
                   `("LD_LIBRARY_PATH" ":" prefix
                     (,(string-append lib ":" nss "/lib/nss:" gtk+ "/lib:"
                                      mesa "/lib:" udev "/lib")))
                   ;; Avoid file manager crash.  See <https://bugs.gnu.org/26593>.
                   `("XDG_DATA_DIRS" ":" prefix (,(string-append gtk+ "/share"))))
                 #t)))))))
    (native-inputs
     `(("bison" ,bison)
       ("gcc" ,gcc-8)
       ("gn" ,gn)
       ("gperf" ,gperf)
       ("ninja" ,ninja)
       ("node" ,node)
       ("pkg-config" ,pkg-config)
       ("which" ,which)
       ("yasm" ,yasm)

       ;; This file contains defaults for new user profiles.
       ("master-preferences" ,(local-file "chromium-master-preferences.json"))

       ("python-beautifulsoup4" ,python2-beautifulsoup4)
       ("python-html5lib" ,python2-html5lib)
       ("python" ,python-2)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("atk" ,atk)
       ("cups" ,cups)
       ("curl" ,curl)
       ("dbus" ,dbus)
       ("dbus-glib" ,dbus-glib)
       ("expat" ,expat)
       ("flac" ,flac)
       ("ffmpeg" ,ffmpeg)
       ("fontconfig" ,fontconfig)
       ("freetype" ,freetype)
       ("gdk-pixbuf" ,gdk-pixbuf)
       ("glib" ,glib)
       ("gtk+" ,gtk+)
       ("harfbuzz" ,harfbuzz)
       ("icu4c" ,icu4c)
       ("jsoncpp" ,jsoncpp)
       ("lcms" ,lcms)
       ("libevent" ,libevent)
       ("libffi" ,libffi)
       ("libjpeg-turbo" ,libjpeg-turbo)
       ("libpng" ,libpng)
       ;;("libsrtp" ,libsrtp)
       ("libvpx" ,libvpx/chromium)
       ("libwebp" ,libwebp)
       ("libx11" ,libx11)
       ("libxcb" ,libxcb)
       ("libxcomposite" ,libxcomposite)
       ("libxcursor" ,libxcursor)
       ("libxdamage" ,libxdamage)
       ("libxext" ,libxext)
       ("libxfixes" ,libxfixes)
       ("libxi" ,libxi)
       ("libxkbcommon" ,libxkbcommon)
       ("libxml2" ,libxml2)
       ("libxrandr" ,libxrandr)
       ("libxrender" ,libxrender)
       ("libxscrnsaver" ,libxscrnsaver)
       ("libxslt" ,libxslt)
       ("libxtst" ,libxtst)
       ("mesa" ,mesa)
       ("minizip" ,minizip)
       ("mit-krb5" ,mit-krb5)
       ("nss" ,nss)
       ("openh264" ,openh264)
       ("openjpeg" ,openjpeg)                          ;PDFium only
       ("openssl" ,openssl)
       ("opus" ,opus+custom)
       ("pango" ,pango)
       ("pciutils" ,pciutils)
       ("pulseaudio" ,pulseaudio)
       ("re2" ,re2)
       ("snappy" ,snappy)
       ("speech-dispatcher" ,speech-dispatcher)
       ("udev" ,eudev)
       ("valgrind" ,valgrind)
       ("vulkan-headers" ,vulkan-headers)))
    (home-page "https://www.chromium.org/")
    (description
     "Chromium is a web browser designed for speed and security.  This
version incorporates features from
@url{https://github.com/gcarq/inox-patchset,the Inox patchset} and
@url{https://github.com/Eloston/ungoogled-chromium,ungoogled-chromium} in
order to protect the users privacy.")
    ;; Chromium is developed as BSD-3, but bundles a large number of third-party
    ;; components with other licenses.  For full information, see chrome://credits.
    (license (list license:bsd-3
                   license:bsd-2
                   license:expat
                   license:asl2.0
                   license:mpl1.1
                   license:mpl2.0
                   license:public-domain
                   license:isc
                   (license:non-copyleft "chrome://credits"
                                         "See chrome://credits for more information.")
                   license:lgpl2.1+))))
