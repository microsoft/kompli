// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ListValidShells.h>
#include <MockContext.h>
#include <algorithm>
#include <cerrno>
#include <set>
#include <string>
#include <utility>

using ComplianceEngine::ListValidShells;
using testing::_;

namespace
{
class ValidShellsTest : public testing::Test
{
protected:
    void SetShells(std::string contents)
    {
        context.SetSpecialFilePath("/etc/shells", context.MakeTempfile(std::move(contents)));
    }

    MockContext context;
};
} // namespace

TEST_F(ValidShellsTest, PreservesCommentWhitespaceDuplicateAndNologinRules)
{
    SetShells(
        "# comment\n/bin/bash\n/bin/bash\n/bin/zsh # comment\n/bin/sh\r\n"
        "/usr/sbin/nologin\n/bin/nologin-wrapper\n/usr/nologin/shell\n"
        "  /bin/ash  \n\n # comment\n/bin/fish");
    auto shells = ListValidShells(context);
    ASSERT_TRUE(shells.HasValue());
    EXPECT_EQ((std::set<std::string>{"", " ", "/bin/bash", "/bin/zsh ", "/bin/sh\r", "/usr/nologin/shell", "  /bin/ash  ", "/bin/fish"}), shells.Value());
}

TEST_F(ValidShellsTest, EmptyFileIsSuccessfulAndMissingFileKeepsCallerError)
{
    SetShells("");
    auto empty = ListValidShells(context);
    ASSERT_TRUE(empty.HasValue());
    EXPECT_TRUE(empty.Value().empty());

    context.SetSpecialFilePath("/etc/shells", context.GetTempdirPath() + "/missing");
    auto missing = ListValidShells(context);
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(EINVAL, missing.Error().code);
    EXPECT_EQ("Failed to open /etc/shells file", missing.Error().message);
}

TEST_F(ValidShellsTest, TerminalLfAndBlankLinesMatchGetlineWithoutStrippingCr)
{
    for (const auto& content : {"/bin/sh", "/bin/sh\n"})
    {
        SetShells(content);
        auto shells = ListValidShells(context);
        ASSERT_TRUE(shells.HasValue());
        EXPECT_EQ((std::set<std::string>{"/bin/sh"}), shells.Value());
    }
    SetShells("\n/bin/sh\r\n\n");
    auto shells = ListValidShells(context);
    ASSERT_TRUE(shells.HasValue());
    EXPECT_EQ((std::set<std::string>{"", "/bin/sh\r"}), shells.Value());
}

TEST_F(ValidShellsTest, ReachedNulAndByteLimitRejectTheWholeSet)
{
    SetShells(std::string("/bin/sh\n/bin/") + std::string(1, '\0') + "bash\n");
    auto nul = ListValidShells(context);
    ASSERT_FALSE(nul.HasValue());
    EXPECT_EQ(EBADMSG, nul.Error().code);

    // The default reader budget includes delimiters and verifies EOF at the
    // limit, rather than accepting a complete-looking prefix as success.
    SetShells("/bin/sh\n" + std::string(1024 * 1024 - 8, 'a'));
    auto exact = ListValidShells(context);
    ASSERT_TRUE(exact.HasValue());
    EXPECT_EQ(2U, exact.Value().size());
    SetShells("/bin/sh\n" + std::string(1024 * 1024 - 7, 'a'));
    auto oversized = ListValidShells(context);
    ASSERT_FALSE(oversized.HasValue());
    EXPECT_EQ(E2BIG, oversized.Error().code);
}

TEST_F(ValidShellsTest, ReachedReadErrorTakesPrecedenceOverCloseError)
{
    SetShells("/bin/bash\n/bin/zsh\n");
    int reads = 0, closes = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (++reads == 1)
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, std::min<std::size_t>(size, 10));
        errno = EIO;
        return -1;
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (closes == 1)
        {
            errno = EBADF;
            return -1;
        }
        return 0;
    });
    auto failed = ListValidShells(context);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_EQ(std::string::npos, failed.Error().message.find("[close:"));
    EXPECT_EQ(2, reads);
    EXPECT_EQ(2, closes);
}

TEST_F(ValidShellsTest, CloseFailureAfterEofIsAnError)
{
    SetShells("/bin/bash\n");
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (closes == 1)
        {
            errno = EIO;
            return -1;
        }
        return 0;
    });
    auto failed = ListValidShells(context);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_EQ(2, closes);
}
