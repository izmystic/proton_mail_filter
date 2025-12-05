# proton_mail_filter
My Proton Mail sieve filter.

## Prerequisites: Create Folders

Before installing the filter, you **must** create the following five folders in your Proton Mail account. The Sieve script will fail if any of these folders do not exist.

1.  **Updates**
2.  **Purchases**
3.  **Social**
4.  **Forums**
5.  **Promotions**

---

## Installation

This script must be installed as a **Custom filter** in your Proton Mail settings.

1.  **Log in** to your Proton Mail account.
2.  Go to **Settings** -> **All settings**.
3.  Navigate to **Proton Mail** -> **Filters**.
4.  Click the **Add sieve filter** button.
5.  Give your filter a descriptive **Name** (e.g., "Main Sieve Filter").
6.  **Copy the full content** of the `proton_mail_filter.sieve` script.
7.  **Paste** the content into the text box.
8.  Click **Save**.

The script will now run automatically on all new incoming emails.

### Tip for Existing Emails
To apply the filter rules to messages already in your inbox, go to **Settings** -> **Filters**, click the **down arrow** next to your filter's name, and select **Apply to existing messages**.
