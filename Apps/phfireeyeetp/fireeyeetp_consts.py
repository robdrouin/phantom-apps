# Define your constants here
FIREEYEETP_US_BASE_PATH = "https://etp.us.fireeye.com/"
FIREEYEETP_EU_BASE_PATH = "https://etp.eu.fireeye.com/"
FIREEYEETP_AP_BASE_PATH = "https://etp.ap.fireeye.com/"
FIREETEETP_API_PATH = "api/v1/"
FIREETEETP_LIST_ALERTS_ENDPOINT = "alerts"
FIREETEETP_GET_ALERT_ENDPOINT = "alerts/{alertId}"
FIREETEETP_GET_ALERT_CASE_FILES_ENDPOINT = "alerts/{alertId}/downloadzip"
FIREETEETP_GET_ALERT_MALWARE_FILES_ENDPOINT = "alerts/{alertId}/downloadmalware"
FIREETEETP_GET_ALERT_PCAP_FILES_ENDPOINT = "alerts/{alertId}/downloadpcap"
FIREETEETP_LIST_MESSAGE_ATTRIBUTES_ENDPOINT = "messages/trace"
FIREETEETP_GET_MESSAGE_ATTRIBUTES_ENDPOINT = "messages/{etp_message_id}"
FIREETEETP_GET_MESSAGE_TRACE_ENDPOINT = "messages"
FIREETEETP_GET_EMAIL_ENDPOINT = "messages/{etp_message_id}/email"
FIREETEETP_REMEDIATE_EMAILS_ENDPOINT = "messages/remediate"
FIREEYEETP_GET_QUARANTINED_EMAIL_ENDPOINT = "quarantine/email/{etp_message_id}"
FIREEYEETP_BULK_RELEASE_QUARANTINE_EMAILS_ENDPOINT = "quarantine/release/"
FIREEYEETP_RELEASE_QUARANTINED_EMAIL_ENDPOINT = "quarantine/release/{etp_message_id}"
FIREEYEETP_BULK_DELETE_QUARANTINE_EMAILS_ENDPOINT = "quarantine/delete/"
FIREEYEETP_DELETE_QUARANTINED_EMAIL_ENDPOINT = "quarantine/delete/{etp_message_id}"
FIREEYEETP_LIST_QUARANTINED_EMAILS_ENDPOINT = "quarantine"
