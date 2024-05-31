#include <WebTwoFactorAuthentication.hpp>
#include <dlfcn.h>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdbusplus/server/object.hpp>
#include <sys/stat.h>
#include <xyz/openbmc_project/TwoFactorAuthentication/WebTwoFactorAuthentication/server.hpp>
constexpr auto TwoFactorAuthRoot =
    "/xyz/openbmc_project/TwoFactorAuthentication";

using namespace phosphor::logging;

using ::phosphor::logging::elog;
using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::phosphor::logging::report;

using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using IfcBase = sdbusplus::xyz::openbmc_project::TwoFactorAuthentication::
    server::WebTwoFactorAuthentication;

using DbusUserPropVariant =
    std::variant<std::vector<std::string>, std::string, bool>;
static constexpr const char *userService = "xyz.openbmc_project.User.Manager";
static constexpr const char *userAttriIntf =
    "xyz.openbmc_project.User.Attributes";

std::string m_verifycode;
std::string m_channel;

namespace fs = std::filesystem;

class TwoFactorAuthImp : IfcBase {
public:
  /* Define all of the basic class operations:
   *     Not allowed:
   *         - Default constructor to avoid nullptrs.
   *         - Copy operations due to internal unique_ptr.
   *         - Move operations due to 'this' being registered as the
   *           'context' with sdbus.
   *     Allowed:
   *         - Destructor.
   */
  TwoFactorAuthImp() = delete;
  TwoFactorAuthImp(const TwoFactorAuthImp &) = delete;
  TwoFactorAuthImp &operator=(const TwoFactorAuthImp &) = delete;
  TwoFactorAuthImp(TwoFactorAuthImp &&) = delete;
  TwoFactorAuthImp &operator=(TwoFactorAuthImp &&) = delete;

  /** @brief Constructor to put object onto bus at a dbus path.
   *  @param[in] bus - Bus to attach to.
   *  @param[in] path - Path to attach at.
   */
  TwoFactorAuthImp(sdbusplus::bus_t &bus, const char *path)
      : sdbusplus::xyz::openbmc_project::TwoFactorAuthentication::server::
            WebTwoFactorAuthentication(bus, path) {
    // set
  }

  /** @Enable and Disable 2FA with respect to the received user name and channel
   * number.
   *  @param[in] userName- User name for which 2FA status should reflects.
   *  @param[in] channelNumber - channel number for which 2FA status should
   * relects.
   *  @param[in] twoFacStatus - 2FA status which needs to be applied
   * enable/disable.
   *  @param[return] URLVal - URL value on success and null for failure.
   */
  std::string enableTwoFactorAuthentication(std::string userName,
                                            uint8_t channelNumber,
                                            bool twoFacStatus) override {
    std::string url;
    std::string URLVal;
    std::string userObj = "/xyz/openbmc_project/user/", secretFilePath,
                channel = "ch", removeCmd = "rm -r ", channelString;
    int scratch_code[10] = {0};
    int scratch_num = 0;
    int retVal = 0;

    DbusUserPropVariant variant;
    if (userName.empty()) {
      return URLVal;
    }

    if (!(channelNumber == AMI_2FA_CHANNEL_SUPPORT)) {
      std::cout << "Channel Not Supported!!!" << std::endl;
      return URLVal;
    }

    if (twoFacStatus) {

      retVal = create_secretURL(userName, channelNumber, URLVal, scratch_code,
                                &scratch_num);
      if (retVal < 0) {
        return URLVal;
      }
      std::cout << URLVal << scratch_num << std::endl;
    } else {
      channelString = std::to_string(channelNumber);
      secretFilePath =
          SECRET_PATH + channel + channelString + "/" + userName.c_str();
      removeCmd.append(secretFilePath);
      if (system(removeCmd.c_str()) == -1) {
        std::cout << "remove failure" << removeCmd << std::endl;
        return URLVal;
      }
    }
    std::cout << URLVal << scratch_num << std::endl;

    // update enable status
    variant = twoFacStatus;
    userObj.append(userName);
    setDbusProperty(userService, userObj, userAttriIntf, "TwoFacEnableStatus",
                    variant);
    return URLVal;
  }

  /** @brief Trigger PAM 2FA PAM module and Validate received OTP against user
   * name by communicating with OTP server.
   *  @param[in] userName for which 2FA need to be validated.
   *  @param[in] otpString - OTP value from authenticator application.
   *  @param[return] RetVal - OTP validation result success / fallse.
   */

  bool verifyOTP(std::string userName, std::string otpString) override {
    bool RetVal = false;
    char *ss = NULL;
    int retval;
    std::string Channel_Number = "ch3";
    pam_handle_t *localAuthHandle = NULL; // this gets set by pam_start
    int pam_status = 0;
    m_verifycode = otpString;
    m_channel = Channel_Number;

    static struct pam_conv localConversation = {verifycode_convfn, NULL};

    std::cout << userName << otpString << std::endl;
    if (userName.empty()) {
      return RetVal;
    }
    if (!((otpString.length() == AMI_AUTH_TWO_FAC_KEY_LEN) ||
          (otpString.length() == AMI_AUTH_TWO_FAC_REC_KEY_LEN))) {
      return RetVal;
    }
    std::cout << userName << otpString << std::endl;

    if (pam_start("TFA", userName.data(), &localConversation,
                  &localAuthHandle) != PAM_SUCCESS) {
      std::cout << "pam_start returned failure..please check config files and "
                   "check that tfa exists inside pam.d!!"
                << std::endl;
      goto OUT;
    }

    pam_status = pam_set_item(localAuthHandle, PAM_CONV,
                              (const void *)&localConversation);
    if (pam_status != PAM_SUCCESS) {
      std::cout << "pam_set_item failed while using converstation" << std::endl;
      goto OUT;
    }

    pam_status = pam_set_item(localAuthHandle, PAM_SERVICE, "TFA");
    pam_get_item(localAuthHandle, PAM_SERVICE, (const void **)&ss);

    if (pam_status != PAM_SUCCESS) {
      std::cout << "pam_set_item failed while setting the service" << std::endl;
      goto OUT;
    }

    retval = pam_authenticate(localAuthHandle, 0);
    if (retval != PAM_SUCCESS) {
      std::cout << "pam_authenticate returned failure ERROR=" << retval
                << std::endl;
      pam_end(localAuthHandle, retval);
      return false;
    }

    return true;

  OUT:
    if (pam_end(localAuthHandle, PAM_SUCCESS) != PAM_SUCCESS) {
      return false;
    }
    return false;
  }

private:
  /** @brief Trigger PAM 2FA PAM module and Validate received OTP against user.
   *  @param[in] service - service path for particular dbus call.
   *  @param[in] objPath - objpath path for particular dbus call.
   *  @param[in] interface - interface path for particular dbus call.
   *  @param[in] property - property name for particular dbus call.
   *  @param[in] value - dubs set propertie value particular dbus call.
   *  @param[return] void - none.
   */
  void setDbusProperty(const std::string &service, const std::string &objPath,
                       const std::string &interface,
                       const std::string &property,
                       DbusUserPropVariant &value) {
    auto bus = sdbusplus::bus::new_default();
    try {
      auto method =
          bus.new_method_call(service.c_str(), objPath.c_str(),
                              "org.freedesktop.DBus.Properties", "Set");
      method.append(interface, property, value);
      bus.call(method);
    } catch (const sdbusplus::exception_t &e) {
      std::cerr << "Error in setDbusproperty \n";
    }
  }

  /** @brief Trigger PAM 2FA PAM module and Validate received OTP against user.
   *  @param[in] service - service path for particular dbus call.
   *  @param[in] objPath - objpath path for particular dbus call.
   *  @param[in] interface - interface path for particular dbus call.
   *  @param[in] property - property name for particular dbus call.
   *  @param[out] value - dubs get propertie value particular dbus call.
   *  @param[return] void - none.
   */
  void getDbusProperty(const std::string &service, const std::string &objPath,
                       const std::string &interface,
                       const std::string &property,
                       DbusUserPropVariant &value) {
    auto bus = sdbusplus::bus::new_default();
    try {
      auto method =
          bus.new_method_call(service.c_str(), objPath.c_str(),
                              "org.freedesktop.DBus.Properties", "Get");

      method.append(interface, property);

      auto reply = bus.call(method);
      reply.read(value);
    } catch (const sdbusplus::exception_t &e) {
      std::cerr << "Fail to getDbusProperty" << std::endl;
    }
  }

  /** @brief Function will encoded value.
   *  @param[in] s - url value which needs to be encoded.
   *  @param[return] ret - encode url value.
   */
  const char *urlEncode(const char *s) {
    const size_t size = 3 * strlen(s) + 1;
    if (size > 10000) {
      // Anything "too big" is too suspect to let through.
      std::cerr << "Error: Generated URL would be unreasonably large " << std::endl;
      exit(1);
    }
    char *ret = new(std::nothrow) char[size];
    if (!ret) {
        std::cerr << "Memory allocation failed." << std::endl;
        exit(1);
    } 
    char *d = ret;
    do {
      switch (*s) {
      case '%':
      case '&':
      case '?':
      case '=':
      encode:
        snprintf(d, size - (d - ret), "%%%02X", (unsigned char)*s);
        d += 3;
        break;
      default:
        if ((*s && *s <= ' ') || *s >= '\x7F') {
          goto encode;
        }
        *d++ = *s;
        break;
      }
    } while (*s++);

return ret;
  }

  /** @brief Function will gernerate url code.
   *  @param[in] secret - secret value read from dev/rand.
   *  @param[in] label - label value.
   *  @param[in] encoderURL - encoderURL value.
   *  @param[in] use_totp - totp option which needs to be used for url.
   *  @param[in] issuer - name for particular dbus call.
   *  @param[return] url - created url value corresponds to the input user.
   */
  const char *getURL(const char *secret, const char *label, char **encoderURL,
                     const int use_totp, const char *issuer) {
    const char *encodedLabel = urlEncode(label);
    char *url;
    const char totp = use_totp ? 't' : 'h';
    if (asprintf(&url, "otpauth://%cotp/%s?secret=%s", totp, encodedLabel,
                 secret) < 0) {
      fprintf(stderr,
              "String allocation failed, probably running out of memory.\n");
      _exit(1);
    }

    if (issuer != NULL && strlen(issuer) > 0) {
      // Append to URL &issuer=<issuer>
      const char *encodedIssuer = urlEncode(issuer);
      char *newUrl;
      if (asprintf(&newUrl, "%s&issuer=%s", url, encodedIssuer) < 0) {
        fprintf(stderr,
                "String allocation failed, probably running out of memory.\n");
        _exit(1);
      }
      free((void *)encodedIssuer);
      free(url);
      url = newUrl;
    }

    if (encoderURL) {
      // Show a QR code.
      const char *encoder = "https://www.google.com/chart?chs=200x200&"
                            "chld=M|0&cht=qr&chl=";
      const char *encodedURL = urlEncode(url);

      *encoderURL =
          strcat(strcpy((char *)malloc(
                            (size_t)(strlen(encoder) + strlen(encodedURL) + 1)),
                        encoder),
                 encodedURL);
      free((void *)encodedURL);
    }
    free((void *)encodedLabel);
    return url;
  }

  /** @brief Create Secret URL that generates the QR code.
   *  @param[in] username - user name for which QR needs to be generated.
   *  @param[in] channel_num  - channel number for which QR needs to be
   * generated.
   *  @param[out] url - generated url value.
   *  @param[out] scratch_code  - array of recover codes.
   *  @param[out] scratch_num - number of recovery codes that generated.
   *  @param[out] url - created url value corresponds to the input user.
   *  @param[return] - success or failure.
   */
  int create_secretURL(std::string username, int channel_num, std::string &url,
                       int *scratch_code, int *scratch_num) {
    uint8_t buf[SECRET_BITS / 8 + MAX_SCRATCHCODES * BYTES_PER_SCRATCHCODE];
    static const char totp[] = "\" TOTP_AUTH\n";
    static const char window[] =
        "\" WINDOW_SIZE 3\n"; // default for HOTP is 17\n";
    char
        secret[(SECRET_BITS + BITS_PER_BASE32_CHAR - 1) / BITS_PER_BASE32_CHAR +
               1 /* newline */ + sizeof(totp) + sizeof(window) +
               SCRATCHCODE_LENGTH * (MAX_SCRATCHCODES + 1 /* newline */) +
               1 /* NUL termination character */];
    char hostname[128] = {0};
    char *encoderURL;
    const char *s_url = NULL;
    std::string channel, secret_ch, label, issuer, secret_fn;
    std::string specialChar = "@", specialChar1 = "&", issuerVal = "issuer=";
    int emergency_codes = SCRATCHCODES;
    // HOTP = 0; TOTP = 1
    int use_totp = 1, i = 0, retVal = 0;
    struct stat st;

    memset((secret), 0, sizeof(secret));
    channel = "ch" + std::to_string(channel_num) + "/";
    secret_fn = SECRET_PATH + channel + (const char *)username.c_str() + SECRET;

    std::string user = "root";
    if (gethostname(hostname, sizeof(hostname) - 1)) {
      strcpy(hostname, "unix");
    }

    label = user + specialChar + hostname;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
      return 1;
    }

    if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
    urandom_failure:
      close(fd);
      return 1;
    }

    base32_encode(buf, SECRET_BITS / 8, (uint8_t *)secret, sizeof(secret));

    s_url =
        getURL(secret, label.c_str(), &encoderURL, use_totp, issuer.c_str());

    url = s_url;
    url.append(specialChar1);
    url.append(issuerVal);
    url.append(username);
    free((char *)s_url);
    free(encoderURL);
    strcat(secret, "\n");
    strcat(secret, totp);
    strcat(secret, window);
    for (i = 0; i < emergency_codes; ++i) {
    new_scratch_code:;
      int scratch = 0;
      int j;
      for (j = 0; j < BYTES_PER_SCRATCHCODE; ++j) {
        scratch = 256 * scratch +
                  buf[SECRET_BITS / 8 + BYTES_PER_SCRATCHCODE * i + j];
      }
      int modulus = 1;
      for (j = 0; j < SCRATCHCODE_LENGTH; j++) {
        modulus *= 10;
      }
      scratch = (scratch & 0x7FFFFFFF) % modulus;
      if (scratch < modulus / 10) {
        if (read(fd, buf + (SECRET_BITS / 8 + BYTES_PER_SCRATCHCODE * i),
                 BYTES_PER_SCRATCHCODE) != BYTES_PER_SCRATCHCODE) {
          goto urandom_failure;
        }
        goto new_scratch_code;
      }
      snprintf(strrchr(secret, '\000'), sizeof(secret) - strlen(secret),
               "%08d\n", scratch);

      scratch_code[i] = scratch;
      (*scratch_num)++;
    }

    if (fd > 0) {
      close(fd);
    }
    if (stat(SECRET_PATH, &st) == -1) {
      if (mkdir(SECRET_PATH, 0777) == -1) {
        perror("mkdir");
        goto errout;
      }
    }
    secret_ch = SECRET_PATH + channel;

    if (stat((char *)secret_ch.c_str(), &st) == -1) {
      if (mkdir((char *)secret_ch.c_str(), 0777) == -1) {
        perror("mkdir");
        goto errout;
      }
    }

    secret_ch = secret_ch + username;
    if (stat((char *)secret_ch.c_str(), &st) == -1) {
      if (mkdir((char *)secret_ch.c_str(), 0777) == -1) {
        perror("mkdir");
        goto errout;
      }
    }

    if (system("chmod -R 777 /etc/google_otp") == -1) {
      goto errout;
    }

    fd = open((const char *)secret_fn.c_str(),
              O_WRONLY | O_EXCL | O_CREAT | O_NOFOLLOW | O_TRUNC, 0644);
    if (fd < 0) {
      goto errout;
    }
    retVal = write(fd, secret, strlen(secret));
    if ((retVal < 0) || (retVal > (int)strlen(secret))) {
      close(fd);
    }
    close(fd);
    return 0;

  errout:
    if (fd >= 0) {
      close(fd);
    }
    return 1;
  }

  /** @brief Encode the secret data.
   *  @param[in] data - secret data that needs to be encoded.
   *  @param[in] length  - secret data length.
   *  @param[out] result - encoded data.
   *  @param[return] - success or failure.
   */
  int base32_encode(const uint8_t *data, int length, uint8_t *result,
                    int bufSize) {
    if (length < 0 || length > (1 << 28)) {
      return -1;
    }
    int count = 0;
    if (length > 0) {
      int buffer = data[0];
      int next = 1;
      int bitsLeft = 8;
      while (count < bufSize && (bitsLeft > 0 || next < length)) {
        if (bitsLeft < 5) {
          if (next < length) {
            buffer <<= 8;
            buffer |= data[next++] & 0xFF;
            bitsLeft += 8;
          } else {
            int pad = 5 - bitsLeft;
            buffer <<= pad;
            bitsLeft += pad;
          }
        }
        int index = 0x1F & (buffer >> (bitsLeft - 5));
        bitsLeft -= 5;
        result[count++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[index];
      }
    }
    if (count < bufSize) {
      result[count] = '\000';
    }
    return count;
  }
  static int verifycode_convfn(int num_msg, const struct pam_message **msg,
                               struct pam_response **resp, void *appdata_ptr) {

    struct pam_response *myresp = NULL;
    if (0) {
      msg = msg; /* -Wextra; Fix for unused parameters */
      appdata_ptr = appdata_ptr;
    }

    if (num_msg > 2) {
      std::cout
          << "Encountred more t..han two messages in the pam conversation "
             "function. giving up\n"
          << std::endl;

      *resp = NULL;
      return (PAM_CONV_ERR);
    }

    // allocate as many responses as num messages
    if (NULL == (myresp = (pam_response *)malloc(
                     (size_t)(num_msg * sizeof(struct pam_response))))) {
      std::cout << "Memory Allocation Error \n" << std::endl;
      *resp = NULL;
      return (PAM_BUF_ERR);
    }

    myresp[0].resp_retcode = 0;
    myresp[0].resp = NULL;
    myresp[0].resp = strdup((const char *)m_verifycode.c_str());

    myresp[1].resp_retcode = 0;
    myresp[1].resp = NULL;
    myresp[1].resp = strdup((const char *)m_channel.c_str());

    *resp = myresp;

    return (PAM_SUCCESS);
  }
};

int main(int argc, char **argv) {
  std::ofstream fpchassis;
  fpchassis.open("/tmp/chassis.tmp", std::ios_base::app);
  fpchassis << "Two Fctor Authentication" << std::endl;
  fpchassis.close();

  if (0) {
    argc = argc;
    argv = argv;
  }

  auto bus = sdbusplus::bus::new_default();
  sdbusplus::server::manager_t objManager(
      bus, "xyz.openbmc_project.TwoFactorAuthentication");
  bus.request_name("xyz.openbmc_project.TwoFactorAuthentication");
  auto manager = std::make_unique<TwoFactorAuthImp>(bus, TwoFactorAuthRoot);

  // Wait for client request
  bus.process_loop();

  return -1;
}
