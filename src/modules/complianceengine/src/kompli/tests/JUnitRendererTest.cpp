// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <JUnitRenderer.hpp>
#include <cerrno>
#include <gtest/gtest.h>
#include <string>

using ComplianceEngine::Kompli::RenderJUnit;

namespace
{
bool Contains(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}
} // namespace

TEST(JUnitRendererTest, EmptyRulesProduceEmptySuite)
{
    auto r = RenderJUnit(R"({"action":"Audit","rules":[]})", "mysuite");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    EXPECT_TRUE(Contains(r.Value(), "<testsuite name=\"mysuite\" tests=\"0\" failures=\"0\" skipped=\"0\">"));
    EXPECT_TRUE(Contains(r.Value(), "</testsuites>"));
}

TEST(JUnitRendererTest, CompliantRuleIsBarePassingTestcase)
{
    const std::string json = R"({"rules":[{"id":"1.1","title":"Rule A title","ruleName":"RuleA","status":"Compliant","indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "<testcase classname=\"1.1\" name=\"Rule A title\"/>"));
    EXPECT_FALSE(Contains(r.Value(), "<failure"));
    EXPECT_TRUE(Contains(r.Value(), "tests=\"1\" failures=\"0\""));
}

TEST(JUnitRendererTest, NonCompliantRuleHasFailureWithIndicatorBody)
{
    const std::string json = R"({"rules":[{"id":"2.3","title":"Rule B title","ruleName":"RuleB","status":"NonCompliant",)"
                             R"("indicators":[{"procedure":"AuditFailure","status":"NonCompliant",)"
                             R"("indicators":[{"message":"bad thing","status":"NonCompliant"}]}]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "<testcase classname=\"2.3\" name=\"Rule B title\">"));
    EXPECT_TRUE(Contains(r.Value(), "<failure message=\"Rule is non-compliant\" type=\"NonCompliant\">"));
    EXPECT_TRUE(Contains(r.Value(), "Rule: RuleB"));
    EXPECT_TRUE(Contains(r.Value(), "Indicators:"));
    EXPECT_TRUE(Contains(r.Value(), "- AuditFailure [NonCompliant]"));
    EXPECT_TRUE(Contains(r.Value(), "- bad thing [NonCompliant]"));
    EXPECT_TRUE(Contains(r.Value(), "tests=\"1\" failures=\"1\""));
}

TEST(JUnitRendererTest, NestedIndicatorsAreIndentedByDepth)
{
    const std::string json = R"({"rules":[{"id":"1","ruleName":"R","status":"NonCompliant",)"
                             R"("indicators":[{"message":"top","status":"Compliant",)"
                             R"("indicators":[{"message":"child","status":"Compliant"}]}]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    // depth 0 -> two leading spaces; depth 1 -> four leading spaces.
    EXPECT_TRUE(Contains(r.Value(), "  - top [Compliant]"));
    EXPECT_TRUE(Contains(r.Value(), "    - child [Compliant]"));
}

TEST(JUnitRendererTest, ParametersAreRenderedWhenPresent)
{
    const std::string json = R"({"rules":[{"id":"1","ruleName":"R","status":"NonCompliant",)"
                             R"("parameters":{"mask":"0600","owner":"root"},"indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "Parameters:"));
    EXPECT_TRUE(Contains(r.Value(), "- mask: 0600"));
    EXPECT_TRUE(Contains(r.Value(), "- owner: root"));
}

TEST(JUnitRendererTest, XmlSpecialCharsAreEscapedInAttributesAndBody)
{
    const std::string json = R"({"rules":[{"id":"1&1","title":"A & B <c> \"d\"","ruleName":"R","status":"NonCompliant",)"
                             R"("indicators":[{"message":"m<&>\"'","status":"NonCompliant"}]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "classname=\"1&amp;1\""));
    EXPECT_TRUE(Contains(r.Value(), "name=\"A &amp; B &lt;c&gt; &quot;d&quot;\""));
    // Body content is escaped too.
    EXPECT_TRUE(Contains(r.Value(), "m&lt;&amp;&gt;&quot;&apos;"));
    // No raw unescaped angle brackets from the rule data leak into the document.
    EXPECT_FALSE(Contains(r.Value(), "<c>"));
}

TEST(JUnitRendererTest, SuiteNameIsEscaped)
{
    auto r = RenderJUnit(R"({"rules":[]})", "a\"b");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "name=\"a&quot;b\""));
}

TEST(JUnitRendererTest, AttributeWhitespaceUsesCharacterReferences)
{
    auto r = RenderJUnit(R"({"rules":[{"id":"1\t2","title":"A\nB\rC","status":"Compliant","tags":["axis:x\ty"]}]})", "S\tN\nR");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "classname=\"1&#9;2\""));
    EXPECT_TRUE(Contains(r.Value(), "name=\"A&#10;B&#13;C\""));
    EXPECT_TRUE(Contains(r.Value(), "<tag value=\"axis:x&#9;y\"/>"));
    EXPECT_TRUE(Contains(r.Value(), "<testsuite name=\"S&#9;N&#10;R\""));
}

TEST(JUnitRendererTest, MixedRulesCountFailuresCorrectly)
{
    const std::string json = R"({"rules":[)"
                             R"({"id":"1","ruleName":"A","status":"Compliant","indicators":[]},)"
                             R"({"id":"2","ruleName":"B","status":"NonCompliant","indicators":[]},)"
                             R"({"id":"3","ruleName":"C","status":"NonCompliant","indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "tests=\"3\" failures=\"2\""));
}

TEST(JUnitRendererTest, NotApplicableRuleIsSkipped)
{
    const std::string json = R"({"rules":[{"id":"4.1","ruleName":"R","status":"NotApplicable",)"
                             R"("indicators":[{"message":"n/a on this distro","status":"NotApplicable"}]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "<skipped message=\"Rule is not applicable\">"));
    EXPECT_TRUE(Contains(r.Value(), "- n/a on this distro [NotApplicable]"));
    EXPECT_TRUE(Contains(r.Value(), "skipped=\"1\""));
    EXPECT_FALSE(Contains(r.Value(), "<failure"));
}

TEST(JUnitRendererTest, SkippedStatusRendersAsSkipped)
{
    const std::string json = R"({"rules":[{"id":"4.2","title":"Rule title","ruleName":"RuleName","status":"Skipped","indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "<testcase classname=\"4.2\" name=\"Rule title\">"));
    EXPECT_TRUE(Contains(r.Value(), "<skipped message=\"Rule was skipped\">Rule: RuleName"));
    EXPECT_TRUE(Contains(r.Value(), "tests=\"1\" failures=\"0\" skipped=\"1\""));
    EXPECT_FALSE(Contains(r.Value(), "<failure"));
}

TEST(JUnitRendererTest, TagsAreRenderedAndEscapedForEachStatus)
{
    const std::string json = R"({"rules":[)"
                             R"({"id":"1","title":"Pass","status":"Compliant","tags":["level:l1","axis:a&<\""],"indicators":[]},)"
                             R"({"id":"2","title":"Fail","ruleName":"FailRule","status":"NonCompliant","tags":["severity:critical"],"indicators":[]},)"
                             R"({"id":"3","title":"Skip","ruleName":"SkipRule","status":"NotApplicable","tags":["level:l2"],"indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "<tag value=\"level:l1\"/>"));
    EXPECT_TRUE(Contains(r.Value(), "<tag value=\"axis:a&amp;&lt;&quot;\"/>"));
    EXPECT_TRUE(Contains(r.Value(), "<tag value=\"severity:critical\"/>"));
    EXPECT_TRUE(Contains(r.Value(), "<tag value=\"level:l2\"/>"));
    EXPECT_TRUE(Contains(r.Value(), "<testcase classname=\"1\" name=\"Pass\">\n    <tags>"));
    EXPECT_TRUE(Contains(r.Value(), "<testcase classname=\"2\" name=\"Fail\">\n    <tags>"));
    EXPECT_TRUE(Contains(r.Value(), "<testcase classname=\"3\" name=\"Skip\">\n    <tags>"));
    EXPECT_TRUE(Contains(r.Value(), "tests=\"3\" failures=\"1\" skipped=\"1\""));
}

TEST(JUnitRendererTest, AbsentTagsOmitTagsBlock)
{
    const std::string json = R"({"rules":[{"id":"1.1","title":"R","status":"Compliant","indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_FALSE(Contains(r.Value(), "<tags>"));
    EXPECT_TRUE(Contains(r.Value(), "<testcase classname=\"1.1\" name=\"R\"/>"));
}

TEST(JUnitRendererTest, RejectsMalformedTagsWithoutMisreportingThem)
{
    // TM-17: malformed result tags cannot become a passing-looking JUnit report.
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":null}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":"level:l1"}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":["level:l1",42]}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":["a:\u0000b"]}]})", "s").HasValue());
}

TEST(JUnitRendererTest, RejectsInvalidXmlAttributeControls)
{
    const std::string prefix = R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":[")";
    const std::string suffix = R"("]}]})";
    auto tag = RenderJUnit(prefix + R"(owner:Ops\u0001Sec)" + suffix, "s");
    ASSERT_FALSE(tag.HasValue());
    EXPECT_EQ(tag.Error().code, EINVAL);

    auto title = RenderJUnit(R"({"rules":[{"id":"1","title":"R\u0001S","status":"Compliant"}]})", "s");
    ASSERT_FALSE(title.HasValue());
    EXPECT_EQ(title.Error().code, EINVAL);

    auto id = RenderJUnit(R"({"rules":[{"id":"1\u0001S","title":"R","status":"Compliant"}]})", "s");
    ASSERT_FALSE(id.HasValue());
    EXPECT_EQ(id.Error().code, EINVAL);

    auto suite = RenderJUnit(R"({"rules":[]})", "Suite\x01Name");
    ASSERT_FALSE(suite.HasValue());
    EXPECT_EQ(suite.Error().code, EINVAL);
}

TEST(JUnitRendererTest, RejectsMalformedTestcaseId)
{
    auto nul = RenderJUnit(R"({"rules":[{"id":"1\u0000suffix","title":"R","status":"Compliant"}]})", "s");
    ASSERT_FALSE(nul.HasValue());
    EXPECT_EQ(nul.Error().code, EINVAL);
    EXPECT_NE(nul.Error().message.find("classname"), std::string::npos);

    auto nonString = RenderJUnit(R"({"rules":[{"id":12,"title":"R","status":"Compliant"}]})", "s");
    ASSERT_FALSE(nonString.HasValue());
    EXPECT_EQ(nonString.Error().code, EINVAL);

    auto missing = RenderJUnit(R"({"rules":[{"title":"R","status":"Compliant"}]})", "s");
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(missing.Error().code, EINVAL);

    auto empty = RenderJUnit(R"({"rules":[{"id":"","title":"R","status":"Compliant"}]})", "s");
    ASSERT_FALSE(empty.HasValue());
    EXPECT_EQ(empty.Error().code, EINVAL);
}

TEST(JUnitRendererTest, RejectsTrailingDataAndEmbeddedInputNul)
{
    const std::string json = R"({"rules":[]})";
    EXPECT_TRUE(RenderJUnit(json + " \n\t", "s").HasValue());
    for (const auto& malformed : {json + "{}", json + " garbage", json + "\v", json + std::string("\0{}", 3)})
    {
        auto result = RenderJUnit(malformed, "s");
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, EINVAL);
    }
}

TEST(JUnitRendererTest, RejectsMalformedIdsAndEmbeddedNul)
{
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"title":"R","status":"Compliant"}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":null,"title":"R","status":"Compliant"}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":1,"title":"R","status":"Compliant"}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"","title":"R","status":"Compliant"}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"bad\u0000id","title":"R","status":"Compliant"}]})", "s").HasValue());
}

TEST(JUnitRendererTest, RejectsOversizeTagsAndBoundedJUnitOutput)
{
    const std::string tag256 = "x:" + std::string(254, 'a');
    const std::string prefix = R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":[")";
    const std::string suffix = R"("]}]})";
    EXPECT_TRUE(RenderJUnit(prefix + tag256 + suffix, "s").HasValue());

    auto longTag = RenderJUnit(prefix + tag256 + "a" + suffix, "s");
    ASSERT_FALSE(longTag.HasValue());
    EXPECT_NE(longTag.Error().message.find("256 bytes"), std::string::npos);
    EXPECT_FALSE(RenderJUnit(prefix + "x:" + std::string(253, 'a') + "\xC3\xA9" + suffix, "s").HasValue());

    // Each tag is short, but their combined XML expansion exceeds the output cap.
    std::string tags;
    const std::string amplified = "x:" + std::string(200, '&');
    for (size_t i = 0; i < 17000; ++i)
    {
        if (!tags.empty())
        {
            tags += ",";
        }
        tags += "\"" + amplified + "\"";
    }
    auto tooLarge = RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":[)" + tags + R"(]}]})", "s");
    ASSERT_FALSE(tooLarge.HasValue());
    EXPECT_EQ(tooLarge.Error().code, EFBIG);
}

TEST(JUnitRendererTest, LegacyResultUsesRuleNameWhenTitleIsAbsent)
{
    auto result = RenderJUnit(R"({"rules":[{"id":"1","ruleName":"LegacyRule","status":"Compliant"}]})", "s");
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(Contains(result.Value(), "<testcase classname=\"1\" name=\"LegacyRule\"/>"));
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":null,"ruleName":"R","status":"Compliant"}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","status":"Compliant"}]})", "s").HasValue());
}

TEST(JUnitRendererTest, RejectsInvalidXmlCharactersAndUtf8)
{
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":"bad\uFFFE","status":"Compliant"}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":["a:\uFFFF"]}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"NonCompliant","indicators":[{"message":"bad\uFFFE"}]}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[]})", std::string("bad\xC3\x28", 5)).HasValue());

    auto valid = RenderJUnit(R"({"rules":[{"id":"1","title":"\u00E9\uD83D\uDE00","status":"Compliant"}]})", "s");
    ASSERT_TRUE(valid.HasValue()) << valid.Error().message;
}

TEST(JUnitRendererTest, RejectsXmlIllegalControlCharactersInAttributes)
{
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":"bad\u0001title","status":"Compliant"}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":["owner:Ops\u0001Sec"]}]})", "s").HasValue());
    EXPECT_FALSE(RenderJUnit(R"({"rules":[]})", std::string("bad\x01suite", 9)).HasValue());
}

TEST(JUnitRendererTest, InvalidJsonIsError)
{
    EXPECT_FALSE(RenderJUnit("not json", "s").HasValue());
}

TEST(JUnitRendererTest, MissingRulesArrayIsError)
{
    EXPECT_FALSE(RenderJUnit(R"({"action":"Audit"})", "s").HasValue());
}

TEST(JUnitRendererTest, NonObjectRootIsError)
{
    EXPECT_FALSE(RenderJUnit(R"([1,2,3])", "s").HasValue());
}

TEST(JUnitRendererTest, UnknownRuleStatusIsError)
{
    // An unrecognised status must be rejected, not silently rendered as a pass.
    const std::string json = R"({"rules":[{"id":"1","ruleName":"R","status":"Bogus","indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    EXPECT_FALSE(r.HasValue());
}

TEST(JUnitRendererTest, MissingRuleStatusIsError)
{
    // A missing status field must be rejected rather than treated as a pass.
    const std::string json = R"({"rules":[{"id":"1","ruleName":"R","indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    EXPECT_FALSE(r.HasValue());
}

TEST(JUnitRendererTest, ControlCharactersAreNeutralised)
{
    // A control character (U+0001) in a message must not corrupt the XML; it is
    // replaced with a space.
    const std::string json = R"({"rules":[{"id":"1","ruleName":"R","status":"NonCompliant",)"
                             R"("indicators":[{"message":"a\u0001b","status":"NonCompliant"}]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "- a b [NonCompliant]"));
}

TEST(JUnitRendererTest, NonStringParameterIsSerialised)
{
    const std::string json = R"({"rules":[{"id":"1","ruleName":"R","status":"NonCompliant",)"
                             R"("parameters":{"count":5,"enabled":true},"indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "- count: 5"));
    EXPECT_TRUE(Contains(r.Value(), "- enabled: true"));
}

TEST(JUnitRendererTest, NonObjectIndicatorEntriesAreSkipped)
{
    // A malformed (non-object) indicator entry is skipped without crashing.
    const std::string json = R"({"rules":[{"id":"1","ruleName":"R","status":"NonCompliant",)"
                             R"("indicators":["junk",{"message":"real","status":"Compliant"}]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    EXPECT_TRUE(Contains(r.Value(), "- real [Compliant]"));
}
