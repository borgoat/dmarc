mod schema;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use serde_xml_rs::from_str;

    use schema::*;

    use super::*;

    #[test]
    fn it_works() {
        let f: Feedback = from_str(
            r#"<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>5717107811868587391</report_id>
    <date_range>
      <begin>1706832000</begin>
      <end>1706918399</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>azzinna.ro</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
    <np>none</np>
  </policy_published>
  <record>
    <row>
      <source_ip>185.70.43.17</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>azzinna.ro</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>azzinna.ro</domain>
        <result>pass</result>
        <selector>protonmail2</selector>
      </dkim>
      <spf>
        <domain>azzinna.ro</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>
"#,
        )
        .unwrap();

        assert_eq!(
            f,
            Feedback {
                report_metadata: ReportMetadataType {
                    org_name: "google.com".to_string(),
                    email: "noreply-dmarc-support@google.com".to_string(),
                    extra_contact_info: Some(
                        "https://support.google.com/a/answer/2466580".to_string()
                    ),
                    report_id: "5717107811868587391".to_string(),
                    date_range: DateRangeType {
                        begin: 1706832000,
                        end: 1706918399
                    },
                    error: None,
                },
                policy_published: PolicyPublishedType {
                    domain: "azzinna.ro".to_string(),
                    adkim: AlignmentType::R,
                    aspf: AlignmentType::R,
                    p: DispositionType::None,
                    sp: DispositionType::None,
                    pct: 100,
                },
                record: vec![RecordType {
                    row: RowType {
                        source_ip: IpAddr::from_str("185.70.43.17").unwrap(),
                        count: 1,
                        policy_evaluated: Some(PolicyEvaluatedType {
                            disposition: DispositionType::None,
                            dkim: DMARCResultType::Pass,
                            spf: DMARCResultType::Pass,
                            reason: None,
                        }),
                    },
                    identifiers: IdentifierType {
                        header_from: "azzinna.ro".to_string(),
                        envelope_to: None,
                    },
                    auth_results: AuthResultType {
                        dkim: Some(vec![DKIMAuthResultType {
                            domain: "azzinna.ro".to_string(),
                            result: DKIMResultType::Pass,
                            selector: Some("protonmail2".to_string()),
                            human_result: None,
                        }]),
                        spf: vec![SPFAuthResultType {
                            domain: "azzinna.ro".to_string(),
                            result: SPFResultType::Pass,
                        }],
                    },
                }],
            }
        );
    }
}
