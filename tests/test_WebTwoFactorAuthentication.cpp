// Unity build setup:
// TwoFactorAuthImp is defined entirely inside WebTwoFactorAuthentication.cpp
// (no exported header). The only way to test its private algorithmic functions
// (base32_encode, urlEncode, verifycode_convfn) without modifying production
// code is to pull the .cpp into this translation unit and expose private
// members at compile time.
//
// #define private public  — makes all private class members public in this TU
// only. #define main ...        — renames production main() to avoid linker
// conflict
//                           with the test_main.cpp entry point.
//
// sdbusplus and all other headers are included BEFORE the macro, so their
// own class layouts are not affected (include guards prevent re-processing).

// Project header first (per gtest-patterns.md §2: project headers before GTest)
#include "WebTwoFactorAuthentication.hpp"

// Undefine macros that collide with GTest macro names (gtest-patterns.md §2)
#ifdef FAIL
#undef FAIL
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif

// GTest / GMock headers after project headers
#include <gmock/gmock.h>
#include <gtest/gtest.h>

// sdbusplus bus — needed for fixture construction
#include <sdbusplus/bus.hpp>

// Standard library
#include <cstdlib>
#include <cstring>
#include <optional>

// ---- Unity build: expose TwoFactorAuthImp and its private members ----------
// Rename production main() so it does not conflict with test_main.cpp.
#define main production_main_tfa
// Expand 'private' to 'public' so base32_encode, urlEncode, and
// verifycode_convfn become directly callable in this translation unit.
// sdbusplus / phosphor headers already processed above (include guards active),
// so only the TwoFactorAuthImp class definition in the .cpp is affected.
#define private public
#include "../WebTwoFactorAuthentication.cpp"
#undef private
#undef main
// ---------------------------------------------------------------------------

// m_verifycode and m_channel are file-scope globals defined in the production
// .cpp. They are set by verifyOTP() and read by verifycode_convfn().
// Accessed directly here because the unity build places them in this TU.
// Reset in SetUp()/TearDown() to prevent cross-test contamination
// (gtest-patterns.md §3).

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
constexpr const char* kTestDbusPath =
    "/xyz/openbmc_project/TwoFactorAuthentication/test";
constexpr uint8_t kValidChannel = AMI_2FA_CHANNEL_SUPPORT; // 3
static const std::string kBase32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// ---------------------------------------------------------------------------
// Fixture: tests requiring a live sdbusplus bus and TwoFactorAuthImp instance
// ---------------------------------------------------------------------------
class TwoFactorAuthTest : public ::testing::Test
{
  protected:
    std::optional<sdbusplus::bus_t> bus;
    std::unique_ptr<TwoFactorAuthImp> tfa;

    void SetUp() override
    {
        // Reset global state before each test (gtest-patterns.md §3)
        m_verifycode = "";
        m_channel = "";
        try
        {
            bus.emplace(sdbusplus::bus::new_default());
            tfa = std::make_unique<TwoFactorAuthImp>(*bus, kTestDbusPath);
        }
        catch (const std::exception& e)
        {
            GTEST_SKIP() << "D-Bus unavailable: " << e.what();
        }
    }

    void TearDown() override
    {
        tfa.reset();
        bus.reset();
        m_verifycode = "";
        m_channel = "";
    }
};

// ===========================================================================
// Suite 1: verifycode_convfn (static PAM conversation callback)
// No TwoFactorAuthImp instance required — called as a static function.
// ===========================================================================

class VerycodeConvFnTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_verifycode = "123456";
        m_channel = "ch3";
    }

    void TearDown() override
    {
        m_verifycode = "";
        m_channel = "";
    }
};

// Pre-scan finding #7 (High): global state m_verifycode / m_channel is set
// before PAM callback; these tests verify the callback reads them correctly.

TEST_F(VerycodeConvFnTest, TooManyMessages_ReturnsPamConvErr)
{
    // Arrange — num_msg > 2 is the documented rejection path
    constexpr int numMsg = 3;
    const struct pam_message* msgs[3] = {nullptr, nullptr, nullptr};
    struct pam_response* resp = nullptr;

    // Act
    int result =
        TwoFactorAuthImp::verifycode_convfn(numMsg, msgs, &resp, nullptr);

    // Assert
    EXPECT_EQ(result, PAM_CONV_ERR);
    EXPECT_EQ(resp, nullptr);
}

TEST_F(VerycodeConvFnTest, TwoMessages_PopulatesResponsesFromGlobals)
{
    // Arrange — two messages is the expected production call pattern
    constexpr int numMsg = 2;
    const struct pam_message* msgs[2] = {nullptr, nullptr};
    struct pam_response* resp = nullptr;
    m_verifycode = "654321";
    m_channel = "ch3";

    // Act
    int result =
        TwoFactorAuthImp::verifycode_convfn(numMsg, msgs, &resp, nullptr);

    // Assert
    ASSERT_EQ(result, PAM_SUCCESS);
    ASSERT_NE(resp, nullptr);
    ASSERT_NE(resp[0].resp, nullptr);
    EXPECT_STREQ(resp[0].resp, "654321");
    ASSERT_NE(resp[1].resp, nullptr);
    EXPECT_STREQ(resp[1].resp, "ch3");
    EXPECT_EQ(resp[0].resp_retcode, 0);
    EXPECT_EQ(resp[1].resp_retcode, 0);

    // Cleanup — PAM contract: test frees responses allocated by the callback
    free(resp[0].resp);
    free(resp[1].resp);
    free(resp);
}

TEST_F(VerycodeConvFnTest, TwoMessages_BoundaryAtMaxValid_ReturnsSuccess)
{
    // Arrange — exactly 2 messages (boundary condition: 2 is the maximum valid)
    constexpr int numMsg = 2;
    const struct pam_message* msgs[2] = {nullptr, nullptr};
    struct pam_response* resp = nullptr;

    // Act
    int result =
        TwoFactorAuthImp::verifycode_convfn(numMsg, msgs, &resp, nullptr);

    // Assert
    EXPECT_EQ(result, PAM_SUCCESS);
    ASSERT_NE(resp, nullptr);

    // Cleanup
    free(resp[0].resp);
    free(resp[1].resp);
    free(resp);
}

TEST_F(VerycodeConvFnTest, EmptyGlobals_ResponsesAreEmptyStrings)
{
    // Arrange — verify empty global strings produce empty (not null) responses
    m_verifycode = "";
    m_channel = "";
    constexpr int numMsg = 2;
    const struct pam_message* msgs[2] = {nullptr, nullptr};
    struct pam_response* resp = nullptr;

    // Act
    int result =
        TwoFactorAuthImp::verifycode_convfn(numMsg, msgs, &resp, nullptr);

    // Assert
    ASSERT_EQ(result, PAM_SUCCESS);
    ASSERT_NE(resp, nullptr);
    EXPECT_STREQ(resp[0].resp, "");
    EXPECT_STREQ(resp[1].resp, "");

    // Cleanup
    free(resp[0].resp);
    free(resp[1].resp);
    free(resp);
}

TEST_F(VerycodeConvFnTest, SpecialCharsInGlobals_ArePreservedInResponse)
{
    // Arrange — OTP and channel with special characters
    m_verifycode = "!@#$%^";
    m_channel = "ch3/extra";
    constexpr int numMsg = 2;
    const struct pam_message* msgs[2] = {nullptr, nullptr};
    struct pam_response* resp = nullptr;

    // Act
    int result =
        TwoFactorAuthImp::verifycode_convfn(numMsg, msgs, &resp, nullptr);

    // Assert — strdup preserves the full string including special characters
    ASSERT_EQ(result, PAM_SUCCESS);
    ASSERT_NE(resp, nullptr);
    EXPECT_STREQ(resp[0].resp, "!@#$%^");
    EXPECT_STREQ(resp[1].resp, "ch3/extra");

    // Cleanup
    free(resp[0].resp);
    free(resp[1].resp);
    free(resp);
}

// ===========================================================================
// Suite 2: enableTwoFactorAuthentication — input validation paths
// (Pre-scan findings #1, #2, #10)
// ===========================================================================

TEST_F(TwoFactorAuthTest, EnableTFA_EmptyUserName_ReturnsEmptyString)
{
    // Pre-scan finding #10 (Medium): silent failure — empty userName returns ""
    // Act
    std::string result =
        tfa->enableTwoFactorAuthentication("", kValidChannel, true);

    // Assert — empty userName triggers immediate early return
    EXPECT_TRUE(result.empty());
}

TEST_F(TwoFactorAuthTest, EnableTFA_ChannelZero_ReturnsEmptyString)
{
    // Arrange — channel 0 is below AMI_AUTH_MIN_CH_NO (1), not supported
    std::string result =
        tfa->enableTwoFactorAuthentication("testuser", 0, true);

    // Assert — unsupported channel returns ""
    EXPECT_TRUE(result.empty());
}

TEST_F(TwoFactorAuthTest, EnableTFA_ChannelOne_ReturnsEmptyString)
{
    std::string result =
        tfa->enableTwoFactorAuthentication("testuser", 1, true);
    EXPECT_TRUE(result.empty());
}

TEST_F(TwoFactorAuthTest, EnableTFA_ChannelTwo_ReturnsEmptyString)
{
    std::string result =
        tfa->enableTwoFactorAuthentication("testuser", 2, true);
    EXPECT_TRUE(result.empty());
}

TEST_F(TwoFactorAuthTest, EnableTFA_ChannelFour_ReturnsEmptyString)
{
    // Arrange — channel 4 is above AMI_2FA_CHANNEL_SUPPORT (3), not supported
    std::string result =
        tfa->enableTwoFactorAuthentication("testuser", 4, true);
    EXPECT_TRUE(result.empty());
}

TEST_F(TwoFactorAuthTest, EnableTFA_ChannelMaxValue_ReturnsEmptyString)
{
    // Arrange — uint8_t max (255) is not the supported channel (3)
    std::string result =
        tfa->enableTwoFactorAuthentication("testuser", 255, true);
    EXPECT_TRUE(result.empty());
}

TEST_F(TwoFactorAuthTest, EnableTFA_Disable_DockerFilesystem_DoesNotCrash)
{
    // Arrange — twoFacStatus=false triggers system("rm -r ...") path.
    // /etc/google_otp/ch3/testuser does not exist in Docker; rm returns 1
    // (not -1), so system() != -1 and execution continues to setDbusProperty.
    // setDbusProperty will fail (no User.Manager on session bus) but is caught
    // internally. Function returns "". See meson.md §9.1 (read-only paths).
    EXPECT_NO_FATAL_FAILURE({
        std::string result = tfa->enableTwoFactorAuthentication(
            "testuser", kValidChannel, false);
        // Result is always empty on the disable path (no URL to return)
        (void)result;
    });
}

// Pre-scan finding #1 (Critical): command injection via userName in system()
// call
TEST_F(TwoFactorAuthTest, EnableTFA_DisableWithShellMetachars_DoesNotCrash)
{
    // Arrange — userName with shell metacharacters.
    // Production bug: system("rm -r /etc/google_otp/ch3/user; echo INJECTED")
    // executes both rm and echo. This test documents the behavior as a living
    // specification; fixing requires replacing system() with std::filesystem.
    // In Docker, /etc/google_otp does not exist so rm exits 1 (not -1).
    std::string injectedUser = "user; echo INJECTED";

    // Act — must not crash despite the injection executing in the shell
    EXPECT_NO_FATAL_FAILURE({
        std::string result = tfa->enableTwoFactorAuthentication(
            injectedUser, kValidChannel, false);
        (void)result;
    });
}

TEST_F(TwoFactorAuthTest, EnableTFA_DisableWithPathTraversal_DoesNotCrash)
{
    // Pre-scan finding #1: path traversal in userName
    // removeCmd = "rm -r /etc/google_otp/ch3/../../etc/passwd"
    // In Docker, /etc/google_otp does not exist; rm fails gracefully.
    std::string traversalUser = "../../etc/passwd";

    EXPECT_NO_FATAL_FAILURE({
        std::string result = tfa->enableTwoFactorAuthentication(
            traversalUser, kValidChannel, false);
        (void)result;
    });
}

// ===========================================================================
// Suite 3: verifyOTP — input validation and global state
// (Pre-scan findings #7, #9)
// ===========================================================================

TEST_F(TwoFactorAuthTest, VerifyOTP_EmptyUserName_ReturnsFalse)
{
    // Act
    bool result = tfa->verifyOTP("", "123456");

    // Assert
    EXPECT_FALSE(result);
}

TEST_F(TwoFactorAuthTest, VerifyOTP_EmptyOTP_ReturnsFalse)
{
    // Arrange — OTP length 0 is neither 6 nor 8
    bool result = tfa->verifyOTP("testuser", "");
    EXPECT_FALSE(result);
}

TEST_F(TwoFactorAuthTest, VerifyOTP_OTPLengthFive_ReturnsFalse)
{
    // Arrange — length 5 < 6 is invalid
    bool result = tfa->verifyOTP("testuser", "12345");
    EXPECT_FALSE(result);
}

TEST_F(TwoFactorAuthTest, VerifyOTP_OTPLengthSeven_ReturnsFalse)
{
    // Arrange — length 7 is between valid lengths 6 and 8, rejected
    bool result = tfa->verifyOTP("testuser", "1234567");
    EXPECT_FALSE(result);
}

TEST_F(TwoFactorAuthTest, VerifyOTP_OTPLengthNine_ReturnsFalse)
{
    // Arrange — length 9 > 8 is invalid
    bool result = tfa->verifyOTP("testuser", "123456789");
    EXPECT_FALSE(result);
}

TEST_F(TwoFactorAuthTest, VerifyOTP_OTPLengthOne_ReturnsFalse)
{
    bool result = tfa->verifyOTP("testuser", "1");
    EXPECT_FALSE(result);
}

// NOTE: Tests calling verifyOTP() with non-empty userName AND valid OTP length
// (6 or 8) reach pam_authenticate → verifycode_convfn. The callback has a
// production bug: it always writes myresp[0] and myresp[1] regardless of
// num_msg. When PAM sends num_msg=1 (typical for authentication), writing
// myresp[1] is a heap overflow, causing SIGABRT under MALLOC_PERTURB_ in
// Docker. These tests are excluded until the production bug in
// verifycode_convfn is fixed (see pre-scan finding #11).
// Global-state-before-PAM behavior is verified via the empty-userName path
// instead (VerifyOTP_EmptyUserName_GlobalsSetBeforeEarlyReturn below).

TEST_F(TwoFactorAuthTest, VerifyOTP_EmptyUserName_GlobalsSetBeforeEarlyReturn)
{
    // Pre-scan finding #7: globals are assigned BEFORE the empty-userName
    // guard check, so they are always set when verifyOTP is called.
    m_verifycode = "previous";
    m_channel = "previous";

    // Act — empty userName triggers early return AFTER globals are set
    bool result = tfa->verifyOTP("", "654321");

    // Assert — returned false; globals are updated despite early return
    EXPECT_FALSE(result);
    EXPECT_EQ(m_verifycode, "654321");
    EXPECT_EQ(m_channel, "ch3");
}

TEST_F(TwoFactorAuthTest, VerifyOTP_InvalidOTPLength_GlobalsSetBeforeReturn)
{
    // Pre-scan finding #7: globals are set before OTP length validation too
    m_verifycode = "old";
    m_channel = "old";

    // Act — OTP length 5 triggers early return AFTER globals are set
    bool result = tfa->verifyOTP("testuser", "99999");

    // Assert
    EXPECT_FALSE(result);
    EXPECT_EQ(m_verifycode, "99999");
    EXPECT_EQ(m_channel, "ch3");
}

// Pre-scan finding #9 (Medium): OTP length 6 with non-digit content passes
// length check and reaches PAM. Cannot be tested directly in Docker because
// pam_authenticate → verifycode_convfn causes SIGABRT (production heap
// overflow, see note above). The gap is documented here as a living
// specification finding.

// ===========================================================================
// Suite 4: base32_encode — pure computation (no side effects)
// ===========================================================================

TEST_F(TwoFactorAuthTest, Base32Encode_NegativeLength_ReturnsMinusOne)
{
    // Arrange
    uint8_t result[16] = {};

    // Act
    int ret = tfa->base32_encode(nullptr, -1, result, sizeof(result));

    // Assert — guard rejects negative length
    EXPECT_EQ(ret, -1);
}

TEST_F(TwoFactorAuthTest, Base32Encode_LengthExceedsMax_ReturnsMinusOne)
{
    // Arrange — (1 << 28) + 1 exceeds the maximum valid length
    uint8_t result[16] = {};

    // Act
    int ret =
        tfa->base32_encode(nullptr, (1 << 28) + 1, result, sizeof(result));

    // Assert — guard rejects oversized length
    EXPECT_EQ(ret, -1);
}

TEST_F(TwoFactorAuthTest, Base32Encode_ZeroLength_ReturnsZeroWithNullTerminator)
{
    // Arrange
    uint8_t result[16] = {0xFF}; // pre-fill to verify null is written

    // Act
    int ret = tfa->base32_encode(nullptr, 0, result, sizeof(result));

    // Assert — empty input produces null-terminated empty output
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(result[0], '\0');
}

TEST_F(TwoFactorAuthTest, Base32Encode_OneByte_AllZeros_EncodesToAA)
{
    // Known encoding: 0x00 → "AA" (8 input bits → 5+3 → padded to 5+5 = 2
    // chars)
    uint8_t data[] = {0x00};
    uint8_t result[16] = {};

    // Act
    int ret = tfa->base32_encode(data, 1, result, sizeof(result));

    // Assert
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(result[0], 'A');
    EXPECT_EQ(result[1], 'A');
    EXPECT_EQ(result[2], '\0');
}

TEST_F(TwoFactorAuthTest, Base32Encode_OneByte_AllOnes_EncodesTo74)
{
    // Known encoding: 0xFF → "74"
    // bits 7-3 of 0xFF = 11111 = 31 → '7'; remaining 3 bits 000 padded → 00100
    // = 28... wait Recalculate: 0xFF=11111111. Take 5 high bits: 11111=31→'7'.
    // Remaining 3 bits: 111, pad 2 zeros → 11100 = 28 →
    // "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[28] = '4'
    uint8_t data[] = {0xFF};
    uint8_t result[16] = {};

    // Act
    int ret = tfa->base32_encode(data, 1, result, sizeof(result));

    // Assert
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(result[0], '7');
    EXPECT_EQ(result[1], '4');
}

TEST_F(TwoFactorAuthTest, Base32Encode_TwoZeroBytes_EncodesToAAAA)
{
    // Known encoding: 0x00 0x00 → "AAAA" (16 bits → 5+5+5+1 padded → 4 chars)
    uint8_t data[] = {0x00, 0x00};
    uint8_t result[16] = {};

    // Act
    int ret = tfa->base32_encode(data, 2, result, sizeof(result));

    // Assert
    EXPECT_EQ(ret, 4);
    EXPECT_STREQ(reinterpret_cast<char*>(result), "AAAA");
}

TEST_F(TwoFactorAuthTest, Base32Encode_AllOutputChars_AreFromBase32Alphabet)
{
    // Arrange — 5 bytes encode to exactly 8 base32 chars with no padding needed
    uint8_t data[] = {0xAB, 0xCD, 0xEF, 0x12, 0x34};
    uint8_t result[16] = {};

    // Act
    int ret = tfa->base32_encode(data, 5, result, sizeof(result));

    // Assert — every output character must be from the base32 alphabet
    ASSERT_GT(ret, 0);
    for (int i = 0; i < ret; ++i)
    {
        EXPECT_NE(kBase32Alphabet.find(static_cast<char>(result[i])),
                  std::string::npos)
            << "Character '" << result[i] << "' at index " << i
            << " is not in the base32 alphabet";
    }
}

TEST_F(TwoFactorAuthTest, Base32Encode_SmallBuffer_TruncatesOutput)
{
    // Arrange — 5 bytes would need 8 chars; buffer only holds 4
    uint8_t data[] = {0xAB, 0xCD, 0xEF, 0x12, 0x34};
    constexpr int kSmallBuf = 4;
    uint8_t result[kSmallBuf] = {};

    // Act
    int ret = tfa->base32_encode(data, 5, result, kSmallBuf);

    // Assert — returns bufSize (buffer full, no null when buffer is exactly
    // full)
    EXPECT_EQ(ret, kSmallBuf);
}

TEST_F(TwoFactorAuthTest, Base32Encode_FiveBytes_ReturnEightChars)
{
    // 5 bytes = 40 bits; 40 / 5 = 8 base32 characters (no padding needed)
    uint8_t data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t result[16] = {};

    // Act
    int ret = tfa->base32_encode(data, 5, result, sizeof(result));

    // Assert
    EXPECT_EQ(ret, 8);
    EXPECT_EQ(result[8], '\0');
}

// ===========================================================================
// Suite 5: urlEncode — pure string transformation
// (Pre-scan finding #5: exit(1) on allocation failure; that path is not
// unit-testable without a custom allocator. Tests focus on encoding logic.)
// ===========================================================================

TEST_F(TwoFactorAuthTest, UrlEncode_EmptyString_ReturnsEmptyEncoding)
{
    // Arrange
    const char* input = "";

    // Act
    const char* encoded = tfa->urlEncode(input);

    // Assert
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded, "");

    // Cleanup — urlEncode returns malloc-allocated memory
    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_PlainAscii_ReturnsUnchanged)
{
    // Arrange — printable ASCII with no special chars should pass through
    const char* input = "helloWorld123";

    // Act
    const char* encoded = tfa->urlEncode(input);

    // Assert
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded, "helloWorld123");

    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_PercentChar_IsPercentEncoded)
{
    // Arrange — '%' triggers the encode case
    const char* input = "a%b";

    // Act
    const char* encoded = tfa->urlEncode(input);

    // Assert — '%' = 0x25 → "%25"
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded, "a%25b");

    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_AmpersandChar_IsPercentEncoded)
{
    const char* input = "a&b";
    const char* encoded = tfa->urlEncode(input);
    ASSERT_NE(encoded, nullptr);
    // '&' = 0x26 → "%26"
    EXPECT_STREQ(encoded, "a%26b");
    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_QuestionMark_IsPercentEncoded)
{
    const char* input = "a?b";
    const char* encoded = tfa->urlEncode(input);
    ASSERT_NE(encoded, nullptr);
    // '?' = 0x3F → "%3F"
    EXPECT_STREQ(encoded, "a%3Fb");
    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_EqualsSign_IsPercentEncoded)
{
    const char* input = "a=b";
    const char* encoded = tfa->urlEncode(input);
    ASSERT_NE(encoded, nullptr);
    // '=' = 0x3D → "%3D"
    EXPECT_STREQ(encoded, "a%3Db");
    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_SpaceChar_IsPercentEncoded)
{
    // ' ' = 0x20 <= ' ', so goto encode path applies
    const char* input = "a b";
    const char* encoded = tfa->urlEncode(input);
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded, "a%20b");
    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_TabChar_IsPercentEncoded)
{
    // '\t' = 0x09 <= ' ' (0x20), so it triggers the encode branch
    const char input[] = {'a', '\t', 'b', '\0'};
    const char* encoded = tfa->urlEncode(input);
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded, "a%09b");
    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_HighByteChar_IsPercentEncoded)
{
    // 0x80 >= 0x7F triggers the encode branch
    const char input[] = {'a', static_cast<char>(0x80), 'b', '\0'};
    const char* encoded = tfa->urlEncode(input);
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded, "a%80b");
    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_0x7F_IsPercentEncoded)
{
    // DEL (0x7F) >= 0x7F triggers the encode branch
    const char input[] = {'x', static_cast<char>(0x7F), 'y', '\0'};
    const char* encoded = tfa->urlEncode(input);
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded, "x%7Fy");
    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_MultipleSpecialChars_AllEncoded)
{
    // Arrange — all four switch-case special chars in one string
    const char* input = "%&?=";
    const char* encoded = tfa->urlEncode(input);
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded, "%25%26%3F%3D");
    free(const_cast<char*>(encoded));
}

TEST_F(TwoFactorAuthTest, UrlEncode_MixedInput_OnlySpecialCharsEncoded)
{
    // Arrange — mix of plain and special chars
    const char* input = "user@host&key=val";
    const char* encoded = tfa->urlEncode(input);
    ASSERT_NE(encoded, nullptr);
    // '@' = 0x40 > ' ' and < 0x7F and not in switch → passes through
    // '&' → %26; '=' → %3D
    EXPECT_STREQ(encoded, "user@host%26key%3Dval");
    free(const_cast<char*>(encoded));
}

// ===========================================================================
// Suite 6: getURL — URL string construction (pure function, no D-Bus/PAM)
// Covers branches: use_totp (TOTP/HOTP), issuer present/absent/null,
// encoderURL present/absent.
// All returned strings are malloc-allocated and must be freed by the test.
// ===========================================================================

TEST_F(TwoFactorAuthTest, GetURL_TOTP_NoIssuer_NoEncoder_ContainsTotpScheme)
{
    // Act — use_totp=1 → totp='t' → "otpauth://totp/..."
    const char* url = tfa->getURL("SECRETKEY", "user@host", nullptr, 1, "");

    // Assert
    ASSERT_NE(url, nullptr);
    EXPECT_NE(strstr(url, "otpauth://totp/"), nullptr);
    EXPECT_NE(strstr(url, "SECRETKEY"), nullptr);

    free(const_cast<char*>(url));
}

TEST_F(TwoFactorAuthTest, GetURL_HOTP_NoIssuer_NoEncoder_ContainsHotpScheme)
{
    // Act — use_totp=0 → totp='h' → "otpauth://hotp/..."
    const char* url = tfa->getURL("SECRETKEY", "user@host", nullptr, 0, "");

    // Assert
    ASSERT_NE(url, nullptr);
    EXPECT_NE(strstr(url, "otpauth://hotp/"), nullptr);

    free(const_cast<char*>(url));
}

TEST_F(TwoFactorAuthTest, GetURL_WithNonEmptyIssuer_AppendsIssuerParam)
{
    // Act — non-empty issuer triggers the issuer-append branch
    const char* url =
        tfa->getURL("SECRETKEY", "user@host", nullptr, 1, "MyIssuer");

    // Assert — issuer appended as "&issuer=MyIssuer"
    ASSERT_NE(url, nullptr);
    EXPECT_NE(strstr(url, "&issuer=MyIssuer"), nullptr);

    free(const_cast<char*>(url));
}

TEST_F(TwoFactorAuthTest, GetURL_EmptyIssuer_NoIssuerParam)
{
    // Act — empty string issuer: strlen("") == 0 → issuer branch skipped
    const char* url = tfa->getURL("SECRETKEY", "user@host", nullptr, 1, "");

    // Assert — "&issuer=" must NOT appear
    ASSERT_NE(url, nullptr);
    EXPECT_EQ(strstr(url, "&issuer="), nullptr);

    free(const_cast<char*>(url));
}

TEST_F(TwoFactorAuthTest, GetURL_NullIssuer_NoIssuerParam)
{
    // Act — NULL issuer: NULL check fails → issuer branch skipped
    const char* url =
        tfa->getURL("SECRETKEY", "user@host", nullptr, 1, nullptr);

    // Assert — "&issuer=" must NOT appear
    ASSERT_NE(url, nullptr);
    EXPECT_EQ(strstr(url, "&issuer="), nullptr);

    free(const_cast<char*>(url));
}

TEST_F(TwoFactorAuthTest, GetURL_WithEncoderURLPtr_SetsQRCodeUrl)
{
    // Act — non-null encoderURL triggers the QR encoder URL branch
    char* encoderURL = nullptr;
    const char* url = tfa->getURL("SECRETKEY", "user@host", &encoderURL, 1, "");

    // Assert — encoderURL gets set to a Google Charts QR URL
    ASSERT_NE(url, nullptr);
    ASSERT_NE(encoderURL, nullptr);
    EXPECT_NE(strstr(encoderURL, "google.com/chart"), nullptr);

    free(const_cast<char*>(url));
    free(encoderURL);
}

TEST_F(TwoFactorAuthTest, GetURL_LabelWithAmpersand_AmpersandEncoded)
{
    // Act — '&' in label is urlEncoded to %26 before embedding in URL
    const char* url = tfa->getURL("SECRETKEY", "user&host", nullptr, 1, "");

    // Assert — the raw '&' must not appear unencoded in the URL path segment
    ASSERT_NE(url, nullptr);
    EXPECT_NE(strstr(url, "%26"), nullptr);

    free(const_cast<char*>(url));
}
