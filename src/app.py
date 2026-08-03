import html

import streamlit as st

from detector import detect_sensitive_data, redact_text


st.set_page_config(
    page_title="Shadow AI Privacy Auditor",
    page_icon="🛡️",
    layout="wide",
)


def create_highlighted_text(text: str, findings: list[dict]) -> str:
    """Create an HTML preview with detected values highlighted."""

    parts: list[str] = []
    current_position = 0

    for finding in findings:
        parts.append(html.escape(text[current_position:finding["start"]]))

        tooltip = html.escape(
            f'{finding["category"]}: {finding["explanation"]}'
        )
        detected_value = html.escape(finding["value"])

        parts.append(
            f'<mark title="{tooltip}" '
            f'style="padding: 3px 5px; border-radius: 4px;">'
            f"{detected_value}</mark>"
        )

        current_position = finding["end"]

    parts.append(html.escape(text[current_position:]))

    return "".join(parts)


st.title("🛡️ Shadow AI Privacy Auditor")

st.write(
    """
    Check text for sensitive or confidential information before sharing it
    with a public AI tool such as ChatGPT, Gemini, or Copilot.
    """
)

st.warning(
    "Use only fictional or synthetic information for testing. "
    "Do not enter real passwords, medical records, financial information, "
    "or confidential company data."
)

with st.expander("What can this application detect?"):
    st.markdown(
        """
        - Email addresses and phone numbers
        - Social Security and payment-card-like numbers
        - Passwords, API keys, and access tokens
        - Medical information
        - Employee, client, patient, and volunteer identifiers
        - Confidential organizational information
        """
    )

sample_text = (
    "Employee ID EMP-4821 belongs to Maya. "
    "Email maya@example.com or call 407-555-0142. "
    "Password: DemoPass123. "
    "The confidential roadmap describes our unreleased product."
)

text = st.text_area(
    "Paste the text you plan to send to an AI tool",
    height=230,
    placeholder=sample_text,
)

scan_clicked = st.button(
    "Scan for sensitive information",
    type="primary",
    use_container_width=True,
)

if scan_clicked:
    if not text.strip():
        st.warning("Please enter some text before scanning.")

    else:
        findings = detect_sensitive_data(text)

        if not findings:
            st.success(
                "No sensitive information was detected. "
                "The original text remains unchanged."
            )

            st.subheader("Reviewed text")
            st.code(text, language=None)

        else:
            critical_count = sum(
                item["severity"] == "Critical" for item in findings
            )
            high_count = sum(
                item["severity"] == "High" for item in findings
            )

            column1, column2, column3 = st.columns(3)

            column1.metric("Total findings", len(findings))
            column2.metric("Critical findings", critical_count)
            column3.metric("High findings", high_count)

            st.error(
                f"{len(findings)} potentially sensitive item(s) detected."
            )

            st.subheader("Highlighted text")

            highlighted_text = create_highlighted_text(text, findings)

            st.markdown(
                f"""
                <div style="
                    line-height: 1.8;
                    padding: 18px;
                    border: 1px solid #d0d7de;
                    border-radius: 8px;
                    background-color: #fafafa;
                    color: #111111;
                ">
                    {highlighted_text}
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.subheader("Findings and risk explanations")

            finding_rows = [
                {
                    "Category": item["category"],
                    "Detected text": item["value"],
                    "Severity": item["severity"],
                    "Why it may be risky": item["explanation"],
                }
                for item in findings
            ]

            st.dataframe(
                finding_rows,
                use_container_width=True,
                hide_index=True,
            )

            st.subheader("Safer redacted version")

            redacted = redact_text(text, findings)

            st.text_area(
                "Review and copy the safer text",
                value=redacted,
                height=190,
            )

            st.download_button(
                "Download redacted text",
                data=redacted,
                file_name="redacted-text.txt",
                mime="text/plain",
                use_container_width=True,
            )

st.divider()

st.caption(
    "Privacy design: this rule-based application does not require an "
    "external AI API and does not intentionally save submitted text."
)
