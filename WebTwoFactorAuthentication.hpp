/*****************************************************************

 Web Two Factor Authentication
 WebTwoFactorAuthentication.hpp

 @brief dbus service for WebTwoFactorAuthentication

 Author: Ramsankar ramsankarr@ami.com

  *****************************************************************/
#ifndef AMI_AUTH_TWO_FAC_HPP
#define AMI_AUTH_TWO_FAC_HPP

#include <boost/process/child.hpp>
#include <boost/process/io.hpp>

// Error Logging
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Attributes/server.hpp>

#include <filesystem>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string>

namespace Base = sdbusplus::xyz::openbmc_project;
using UsersIface = Base::User::server::Attributes;
using Interfaces = sdbusplus::server::object_t<UsersIface>;
// int create_secret(char *username, int channel_num, char *url, int
// *scratch_code, int *scratch_num);
#define AMI_AUTH_MIN_CH_NO 1
#define AMI_AUTH_MAX_CH_NO 8
#define AMI_2FA_CHANNEL_SUPPORT 3
#define AMI_AUTH_TWO_FAC_KEY_LEN 6
#define AMI_AUTH_TWO_FAC_REC_KEY_LEN 8

#define SECRET "/.google_authenticator"
#define SECRET_PATH "/etc/google_otp/"
#define SECRET_BITS 128                         // Must be divisible by eight
#define VERIFICATION_CODE_MODULUS (1000 * 1000) // Six digits
#define SCRATCHCODES 5          // Default number of initial scratchcodes
#define MAX_SCRATCHCODES 10     // Max number of initial scratchcodes
#define SCRATCHCODE_LENGTH 8    // Eight digits per scratchcode
#define BYTES_PER_SCRATCHCODE 4 // 32bit of randomness is enough
#define BITS_PER_BASE32_CHAR 5  // Base32 expands space by 8/5

#define MAX_URL_LEN 1024 // Base32 expands space by 8/5
#endif
