// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <BenchmarkFormatter.hpp>
#include <JUnitRenderer.hpp>
#include <cerrno>
#include <gtest/gtest.h>
#include <pugixml.hpp>
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
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str(), pugi::parse_default | pugi::parse_declaration));
    EXPECT_EQ(std::string("UTF-8"), xml.first_child().attribute("encoding").value());
    auto suite = xml.child("testsuites").child("testsuite");
    ASSERT_TRUE(suite);
    EXPECT_EQ(std::string("mysuite"), suite.attribute("name").value());
    EXPECT_EQ(0u, suite.attribute("tests").as_uint());
    EXPECT_EQ(0u, suite.attribute("failures").as_uint());
    EXPECT_EQ(0u, suite.attribute("skipped").as_uint());
    EXPECT_FALSE(suite.first_child());
}

TEST(JUnitRendererTest, FormatterOutputPreservesIdentityTitleTagsAndCounts)
{
    using namespace ComplianceEngine;
    auto formatter = BenchmarkFormatters::BenchmarkFormatter::Begin(DistributionInfo{});
    ASSERT_TRUE(formatter.HasValue());
    BenchmarkIO::Resource entry;
    entry.benchmarkInfo.framework = "cis";
    entry.benchmarkInfo.distribution = LinuxDistribution::Ubuntu;
    entry.benchmarkInfo.version = "22.04";
    entry.benchmarkInfo.benchmarkVersion = "v2.0.0";
    entry.id = "1.1";
    entry.ruleId = "stable-1";
    entry.ruleName = "RuleName";
    entry.resourceID = "Human <title>";
    entry.tags = {"level:l1", "owner:Ops & Sec"};
    ASSERT_FALSE(formatter.Value().AddEntry(entry, Status::Compliant, "[]", {}, Action::Audit).HasValue());
    entry.id = "1.2";
    ASSERT_FALSE(formatter.Value().AddEntry(entry, Status::NonCompliant, "[]", {}, Action::Audit).HasValue());
    entry.id = "1.3";
    ASSERT_FALSE(formatter.Value().AddSkippedEntry(entry, {}).HasValue());
    auto json = std::move(formatter.Value()).Finish(Status::NonCompliant);
    ASSERT_TRUE(json.HasValue());
    auto rendered = RenderJUnit(json.Value(), "suite");
    ASSERT_TRUE(rendered.HasValue()) << rendered.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(rendered.Value().c_str()));
    auto suite = xml.child("testsuites").child("testsuite");
    ASSERT_TRUE(suite);
    EXPECT_EQ(3u, suite.attribute("tests").as_uint());
    EXPECT_EQ(1u, suite.attribute("failures").as_uint());
    EXPECT_EQ(1u, suite.attribute("skipped").as_uint());
    auto testcase = suite.child("testcase");
    ASSERT_TRUE(testcase);
    EXPECT_EQ(std::string("3:cis6:ubuntu5:22.046:v2.0.03:1.1"), testcase.attribute("classname").value());
    EXPECT_EQ(std::string("Human <title>"), testcase.attribute("name").value());
    auto tag = testcase.child("tags").child("tag");
    ASSERT_TRUE(tag);
    EXPECT_EQ(std::string("level:l1"), tag.attribute("value").value());
    ASSERT_TRUE(tag.next_sibling("tag"));
    EXPECT_EQ(std::string("owner:Ops & Sec"), tag.next_sibling("tag").attribute("value").value());
    EXPECT_FALSE(tag.next_sibling("tag").next_sibling("tag"));
    EXPECT_TRUE(testcase.next_sibling("testcase").child("failure"));
    EXPECT_TRUE(testcase.next_sibling("testcase").next_sibling("testcase").child("skipped"));
}

TEST(JUnitRendererTest, RejectsNulSuffixedAndNonStringStatuses)
{
    for (const auto* status : {R"("Compliant\u0000NonCompliant")", R"("NonCompliant\u0000")", R"("Skipped\u0000")", R"("NotApplicable\u0000")", "null",
             "42", "true", "[]", "{}"})
    {
        auto result = RenderJUnit(std::string(R"({"rules":[{"id":"1","title":"R","status":)") + status + "}]}", "s");
        ASSERT_FALSE(result.HasValue()) << status;
        EXPECT_EQ(result.Error().code, EINVAL);
    }
}

TEST(JUnitRendererTest, ValidatesTagAxisAndValue)
{
    const std::string prefix = R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":[")";
    const std::string suffix = R"("]}]})";
    for (const auto* tag : {"", "severity", ":critical", "severity:", "Severity:critical", "bad_axis:value", "bad axis:value"})
    {
        auto result = RenderJUnit(prefix + tag + suffix, "s");
        ASSERT_FALSE(result.HasValue()) << tag;
        EXPECT_EQ(result.Error().code, EINVAL);
    }
    for (const auto* tag : {"severity:critical", "axis-1:two:parts", "owner:Ops & Sec", "owner:\\u00e9"})
    {
        auto result = RenderJUnit(prefix + tag + suffix, "s");
        ASSERT_TRUE(result.HasValue()) << tag << ": " << result.Error().message;
    }
}

TEST(JUnitRendererTest, CompliantRuleIsBarePassingTestcase)
{
    const std::string json = R"({"rules":[{"id":"1.1","title":"Rule A title","ruleName":"RuleA","status":"Compliant","indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    auto suite = xml.child("testsuites").child("testsuite");
    EXPECT_EQ(1u, suite.attribute("tests").as_uint());
    EXPECT_EQ(0u, suite.attribute("failures").as_uint());
    auto testcase = suite.child("testcase");
    EXPECT_EQ(std::string("1.1"), testcase.attribute("classname").value());
    EXPECT_EQ(std::string("Rule A title"), testcase.attribute("name").value());
    EXPECT_FALSE(testcase.first_child());
}

TEST(JUnitRendererTest, BenchmarkProvenanceDisambiguatesSameRuleId)
{
    const std::string json = R"({"rules":[)"
                             R"({"benchmark":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04","benchmarkVersion":"v2.0.0"},)"
                             R"("id":"1.1","title":"Same title","ruleName":"SameRule","status":"Compliant","indicators":[]},)"
                             R"({"benchmark":{"framework":"stig","distribution":"ubuntu","distributionVersion":"22.04","benchmarkVersion":"v1.0.0"},)"
                             R"("id":"1.1","title":"Same title","ruleName":"SameRule","status":"Compliant","indicators":[]}]})";
    auto result = RenderJUnit(json, "s");
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(Contains(result.Value(), "classname=\"3:cis6:ubuntu5:22.046:v2.0.03:1.1\""));
    EXPECT_TRUE(Contains(result.Value(), "classname=\"4:stig6:ubuntu5:22.046:v1.0.03:1.1\""));
}

TEST(JUnitRendererTest, BenchmarkClassnameEncodingPreventsDelimiterCollisions)
{
    const std::string json = R"({"rules":[)"
                             R"({"benchmark":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04","benchmarkVersion":"v1"},)"
                             R"("id":"part:rule","title":"First","ruleName":"SameRule","status":"Compliant","indicators":[]},)"
                             R"({"benchmark":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04","benchmarkVersion":"v1:part"},)"
                             R"("id":"rule","title":"Second","ruleName":"SameRule","status":"Compliant","indicators":[]}]})";
    auto result = RenderJUnit(json, "s");
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(Contains(result.Value(), "classname=\"3:cis6:ubuntu5:22.042:v19:part:rule\""));
    EXPECT_TRUE(Contains(result.Value(), "classname=\"3:cis6:ubuntu5:22.047:v1:part4:rule\""));
}

TEST(JUnitRendererTest, RejectsEscapedNulInEveryBenchmarkClassnameComponent)
{
    const std::string benchmark = R"("framework":"cis","distribution":"ubuntu","distributionVersion":"22.04","benchmarkVersion":"v1")";
    const std::string prefix = R"({"rules":[{"benchmark":{)";
    const std::string suffix = R"(},"id":"1","title":"R","status":"Compliant"}]})";
    auto baseline = RenderJUnit(prefix + benchmark + suffix, "s");
    ASSERT_TRUE(baseline.HasValue()) << baseline.Error().message;
    EXPECT_TRUE(Contains(baseline.Value(), "classname=\"3:cis6:ubuntu5:22.042:v11:1\""));

    // Every distinct decoded provenance must either encode distinctly or fail,
    // never silently truncate to the baseline classname.
    for (const char* key : {"framework", "distribution", "distributionVersion", "benchmarkVersion"})
    {
        std::string malformed = benchmark;
        const std::string field = "\"" + std::string(key) + "\":\"";
        const auto start = malformed.find(field);
        ASSERT_NE(std::string::npos, start) << key;
        const auto end = malformed.find('"', start + field.size());
        ASSERT_NE(std::string::npos, end) << key;
        malformed.insert(end, R"(\u0000suffix)");
        auto result = RenderJUnit(prefix + malformed + suffix, "s");
        ASSERT_FALSE(result.HasValue()) << key;
        EXPECT_EQ(EINVAL, result.Error().code) << key;
        EXPECT_TRUE(Contains(result.Error().message, key)) << result.Error().message;
    }
}

TEST(JUnitRendererTest, NonCompliantRuleHasFailureWithIndicatorBody)
{
    const std::string json = R"({"rules":[{"id":"2.3","title":"Rule B title","ruleName":"RuleB","status":"NonCompliant",)"
                             R"("indicators":[{"procedure":"AuditFailure","status":"NonCompliant",)"
                             R"("indicators":[{"message":"bad thing","status":"NonCompliant"}]}]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    auto suite = xml.child("testsuites").child("testsuite");
    EXPECT_EQ(1u, suite.attribute("tests").as_uint());
    EXPECT_EQ(1u, suite.attribute("failures").as_uint());
    auto testcase = suite.child("testcase");
    ASSERT_TRUE(testcase);
    EXPECT_EQ(std::string("2.3"), testcase.attribute("classname").value());
    EXPECT_EQ(std::string("Rule B title"), testcase.attribute("name").value());
    auto failure = testcase.child("failure");
    ASSERT_TRUE(failure);
    EXPECT_EQ(std::string("Rule is non-compliant"), failure.attribute("message").value());
    EXPECT_EQ(std::string("NonCompliant"), failure.attribute("type").value());
    EXPECT_TRUE(Contains(failure.child_value(), "Rule: RuleB"));
    EXPECT_TRUE(Contains(failure.child_value(), "Indicators:"));
    EXPECT_TRUE(Contains(failure.child_value(), "- AuditFailure [NonCompliant]"));
    EXPECT_TRUE(Contains(failure.child_value(), "- bad thing [NonCompliant]"));
}

TEST(JUnitRendererTest, NestedIndicatorsAreIndentedByDepth)
{
    const std::string json = R"({"rules":[{"id":"1","ruleName":"R","status":"NonCompliant",)"
                             R"("indicators":[{"message":"top","status":"Compliant",)"
                             R"("indicators":[{"message":"child","status":"Compliant"}]}]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    // depth 0 -> two leading spaces; depth 1 -> four leading spaces.
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    const std::string body = xml.child("testsuites").child("testsuite").child("testcase").child("failure").child_value();
    EXPECT_TRUE(Contains(body, "  - top [Compliant]"));
    EXPECT_TRUE(Contains(body, "    - child [Compliant]"));
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
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    auto testcase = xml.child("testsuites").child("testsuite").child("testcase");
    ASSERT_TRUE(testcase);
    EXPECT_EQ(std::string("1&1"), testcase.attribute("classname").value());
    EXPECT_EQ(std::string("A & B <c> \"d\""), testcase.attribute("name").value());
    EXPECT_TRUE(Contains(testcase.child("failure").child_value(), "m<&>\"'"));
    EXPECT_FALSE(xml.child("testsuites").child("c"));
}

TEST(JUnitRendererTest, SuiteNameIsEscaped)
{
    auto r = RenderJUnit(R"({"rules":[]})", "a\"b");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    EXPECT_EQ(std::string("a\"b"), xml.child("testsuites").child("testsuite").attribute("name").value());
}

TEST(JUnitRendererTest, AttributeWhitespaceUsesCharacterReferences)
{
    auto r = RenderJUnit(R"({"rules":[{"id":"1\t2","title":"A\nB\rC","status":"Compliant","tags":["axis:x\ty"]}]})", "S\tN\nR");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    auto suite = xml.child("testsuites").child("testsuite");
    ASSERT_TRUE(suite);
    EXPECT_EQ(std::string("S\tN\nR"), suite.attribute("name").value());
    auto testcase = suite.child("testcase");
    ASSERT_TRUE(testcase);
    EXPECT_EQ(std::string("1\t2"), testcase.attribute("classname").value());
    EXPECT_EQ(std::string("A\nB\rC"), testcase.attribute("name").value());
    EXPECT_EQ(std::string("axis:x\ty"), testcase.child("tags").child("tag").attribute("value").value());
}

TEST(JUnitRendererTest, UnicodeAndFailureBodyRoundTripWithoutExtraWhitespace)
{
    const std::string json = R"({"rules":[{"id":"\u03B1","title":"\u00E9\uD83D\uDE00","ruleName":"AuditRule","status":"NonCompliant",)"
                             R"("parameters":{"first":"one","second":"two"},"indicators":[{"message":"a\u0001b","status":"NonCompliant"},)"
                             R"({"message":"\u00E9\uD83D\uDE00","status":"Compliant"}]}]})";
    auto result = RenderJUnit(json, "s");
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(result.Value().c_str()));
    auto testcase = xml.child("testsuites").child("testsuite").child("testcase");
    EXPECT_EQ(std::string("\xCE\xB1"), testcase.attribute("classname").value());
    EXPECT_EQ(std::string("\xC3\xA9\xF0\x9F\x98\x80"), testcase.attribute("name").value());
    auto failure = testcase.child("failure");
    ASSERT_TRUE(failure);
    EXPECT_EQ(std::string("Rule: AuditRule\n\nParameters:\n  - first: one\n  - second: two\n\nIndicators:\n"
                          "  - a b [NonCompliant]\n  - \xC3\xA9\xF0\x9F\x98\x80 [Compliant]\n"),
        failure.child_value());
}

TEST(JUnitRendererTest, IndicatorDepthLimitIsPreserved)
{
    std::string indicator = R"({"message":"excluded","status":"Compliant"})";
    for (size_t depth = 0; depth < 16; ++depth)
    {
        indicator = R"({"message":"visible","status":"Compliant","indicators":[)" + indicator + "]}";
    }
    auto result = RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"NonCompliant","indicators":[)" + indicator + R"(]}]})", "s");
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(result.Value().c_str()));
    const std::string body = xml.child("testsuites").child("testsuite").child("testcase").child("failure").child_value();
    EXPECT_FALSE(Contains(body, "excluded"));
    size_t count = 0;
    for (size_t pos = body.find("- visible"); pos != std::string::npos; pos = body.find("- visible", pos + 1))
    {
        ++count;
    }
    EXPECT_EQ(16u, count);
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
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    auto suite = xml.child("testsuites").child("testsuite");
    EXPECT_EQ(1u, suite.attribute("skipped").as_uint());
    auto testcase = suite.child("testcase");
    auto skipped = testcase.child("skipped");
    ASSERT_TRUE(skipped);
    EXPECT_EQ(std::string("Rule is not applicable"), skipped.attribute("message").value());
    EXPECT_TRUE(Contains(skipped.child_value(), "- n/a on this distro [NotApplicable]"));
    EXPECT_FALSE(testcase.child("failure"));
}

TEST(JUnitRendererTest, SkippedStatusRendersAsSkipped)
{
    const std::string json = R"({"rules":[{"id":"4.2","title":"Rule title","ruleName":"RuleName","status":"Skipped","indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    auto suite = xml.child("testsuites").child("testsuite");
    EXPECT_EQ(1u, suite.attribute("tests").as_uint());
    EXPECT_EQ(0u, suite.attribute("failures").as_uint());
    EXPECT_EQ(1u, suite.attribute("skipped").as_uint());
    auto testcase = suite.child("testcase");
    EXPECT_EQ(std::string("4.2"), testcase.attribute("classname").value());
    EXPECT_EQ(std::string("Rule title"), testcase.attribute("name").value());
    auto skipped = testcase.child("skipped");
    ASSERT_TRUE(skipped);
    EXPECT_EQ(std::string("Rule was skipped"), skipped.attribute("message").value());
    EXPECT_TRUE(Contains(skipped.child_value(), "Rule: RuleName"));
    EXPECT_FALSE(testcase.child("failure"));
}

TEST(JUnitRendererTest, TagsAreRenderedAndEscapedForEachStatus)
{
    const std::string json = R"({"rules":[)"
                             R"({"id":"1","title":"Pass","status":"Compliant","tags":["level:l1","axis:a&<\""],"indicators":[]},)"
                             R"({"id":"2","title":"Fail","ruleName":"FailRule","status":"NonCompliant","tags":["severity:critical"],"indicators":[]},)"
                             R"({"id":"3","title":"Skip","ruleName":"SkipRule","status":"NotApplicable","tags":["level:l2"],"indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    auto suite = xml.child("testsuites").child("testsuite");
    EXPECT_EQ(3u, suite.attribute("tests").as_uint());
    EXPECT_EQ(1u, suite.attribute("failures").as_uint());
    EXPECT_EQ(1u, suite.attribute("skipped").as_uint());
    auto pass = suite.child("testcase");
    ASSERT_TRUE(pass);
    EXPECT_EQ(std::string("1"), pass.attribute("classname").value());
    EXPECT_EQ(std::string("Pass"), pass.attribute("name").value());
    auto tag = pass.child("tags").child("tag");
    ASSERT_TRUE(tag);
    EXPECT_EQ(std::string("level:l1"), tag.attribute("value").value());
    EXPECT_EQ(std::string("axis:a&<\""), tag.next_sibling("tag").attribute("value").value());
    auto fail = pass.next_sibling("testcase");
    ASSERT_TRUE(fail);
    EXPECT_EQ(std::string("2"), fail.attribute("classname").value());
    EXPECT_EQ(std::string("severity:critical"), fail.child("tags").child("tag").attribute("value").value());
    EXPECT_TRUE(fail.child("failure"));
    auto skip = fail.next_sibling("testcase");
    ASSERT_TRUE(skip);
    EXPECT_EQ(std::string("3"), skip.attribute("classname").value());
    EXPECT_EQ(std::string("level:l2"), skip.child("tags").child("tag").attribute("value").value());
    EXPECT_TRUE(skip.child("skipped"));
}

TEST(JUnitRendererTest, AbsentTagsOmitTagsBlock)
{
    const std::string json = R"({"rules":[{"id":"1.1","title":"R","status":"Compliant","indicators":[]}]})";
    auto r = RenderJUnit(json, "s");
    ASSERT_TRUE(r.HasValue()) << r.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(r.Value().c_str()));
    auto testcase = xml.child("testsuites").child("testsuite").child("testcase");
    EXPECT_EQ(std::string("1.1"), testcase.attribute("classname").value());
    EXPECT_EQ(std::string("R"), testcase.attribute("name").value());
    EXPECT_FALSE(testcase.child("tags"));
    EXPECT_FALSE(testcase.first_child());
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

TEST(JUnitRendererTest, CompleteInputCheckHandlesNestedObjectsAndEscapedStrings)
{
    const std::string json = R"({"rules":[],"extra":{"text":"} { \" \\","nested":[{},{"text":"\u007d"}]}})";
    for (const auto& input : {json, " \r\n\t" + json, std::string("\xEF\xBB\xBF") + json})
    {
        auto result = RenderJUnit(input + " \t\r\n", "s");
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        for (const auto* suffix : {"{}", "[]", "}", " true", "\f", "\v", " garbage"})
        {
            auto malformed = RenderJUnit(input + suffix, "s");
            ASSERT_FALSE(malformed.HasValue()) << suffix;
            EXPECT_EQ(malformed.Error().code, EINVAL);
        }
    }
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

TEST(JUnitRendererTest, ManyShortTagsFitWithinBoundedJUnitOutput)
{
    // The old 128-byte-per-node allowance rejected this compact XML, even
    // though its actual serialization is well below the 16 MiB limit.
    constexpr size_t tagCount = 66000;
    std::string tags;
    tags.reserve(tagCount * 6);
    for (size_t i = 0; i < tagCount; ++i)
    {
        if (i != 0)
        {
            tags += ',';
        }
        tags += R"("x:a")";
    }
    auto result = RenderJUnit(R"({"rules":[{"id":"1","title":"R","status":"Compliant","tags":[)" + tags + R"(]}]})", "s");
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_LT(result.Value().size(), 16u * 1024 * 1024);

    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(result.Value().c_str()));
    auto testcase = xml.child("testsuites").child("testsuite").child("testcase");
    ASSERT_TRUE(testcase);
    EXPECT_EQ(std::string("R"), testcase.attribute("name").value());
    size_t parsedCount = 0;
    for (auto tag = testcase.child("tags").child("tag"); tag; tag = tag.next_sibling("tag"))
    {
        EXPECT_STREQ("x:a", tag.attribute("value").value());
        ++parsedCount;
    }
    EXPECT_EQ(tagCount, parsedCount);
}

TEST(JUnitRendererTest, LegacyResultUsesRuleNameWhenTitleIsAbsent)
{
    auto result = RenderJUnit(R"({"rules":[{"id":"1","ruleName":"LegacyRule","status":"Compliant"}]})", "s");
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    pugi::xml_document xml;
    ASSERT_TRUE(xml.load_string(result.Value().c_str()));
    auto testcase = xml.child("testsuites").child("testsuite").child("testcase");
    EXPECT_EQ(std::string("1"), testcase.attribute("classname").value());
    EXPECT_EQ(std::string("LegacyRule"), testcase.attribute("name").value());
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
