# Status Page Examples

This document is copied from `examples.zip` and used as an explicit generation reference for the MVP.

## Example 1: API Performance Degradation (SEV-2)

### Initial Update (Investigating)
Posted: Jan 15, 2:30 PM PT

Title: API Performance Degradation
Status: Investigating

Message:
We are currently investigating reports of slower than normal API response times. Some customers may experience delays when making API calls. Our engineering team is actively investigating the issue.

We will provide an update within 30 minutes or as soon as we have more information.

### Update (Identified)
Posted: Jan 15, 2:45 PM PT

Title: API Performance Degradation
Status: Identified

Message:
We have identified the cause of the API performance issues. Our engineering team is implementing a fix. API calls may continue to experience increased response times until the fix is fully deployed.

Affected: API endpoints
Impact: Increased response times, some timeouts may occur

We expect to have this resolved within 30 minutes and will provide updates as we make progress.

### Update (Monitoring)
Posted: Jan 15, 3:15 PM PT

Title: API Performance Degradation
Status: Monitoring

Message:
We have implemented a fix and API response times are returning to normal. We are monitoring the system to ensure stability.

Most customers should see normal performance resuming. We will continue monitoring for the next hour before marking this incident as fully resolved.

### Final Update (Resolved)
Posted: Jan 15, 4:50 PM PT

Title: API Performance Degradation - Resolved
Status: Resolved

Message:
This incident has been resolved. API performance has returned to normal and has remained stable for over 90 minutes.

Summary:
Incident start: ~2:20 PM PT
Incident resolution: ~3:00 PM PT
Total duration: ~40 minutes
Impact: Increased API response times, some requests experienced timeouts

We apologize for any inconvenience this may have caused. If you continue to experience issues, please contact our support team.

## Example 2: Email Delivery Delays (SEV-3)

### Initial Update
Posted: Mar 3, 1:15 PM PT

Title: Email Notification Delays
Status: Investigating

Message:
We are investigating reports of delayed email notifications. Emails are being queued and will be delivered, but may arrive later than expected.

Detection functionality and the web portal are operating normally. Only email notifications are affected.

### Final Update (Resolved)
Posted: Mar 3, 2:45 PM PT

Title: Email Notification Delays - Resolved
Status: Resolved

Message:
Email notification delays have been resolved. All queued emails have been successfully delivered.

Summary:
Duration: ~1.5 hours
Impact: Delayed email notifications (all notifications were successfully delivered)
Product detection and web portal: No impact

Thank you for your patience.

## Style Notes

These examples are the canonical style reference for public incident updates.

## Key Characteristics Of Good Status Page Updates

### Tone

- Professional and empathetic
- Direct and honest without over-sharing
- Avoid technical jargon
- Focus on customer impact, not internal details

### Structure

- `Title`: Clear, concise description of the issue
- `Status`: Investigating | Identified | Monitoring | Resolved
- `Message`: Explain what is happening, what is affected, what the team is doing, and when customers should expect the next update or resolution
 - For `Resolved`, include a short `Summary:` section in plain lines after the main message

For this MVP, treat the examples as style references for the message body. The model should not emit the section labels themselves.

### What To Include

- Customer-facing symptoms such as slower response times or delayed emails
- Affected functionality or features
- Estimated resolution time if known, or the next update timing
- Workarounds if available

### What To Exclude

- Internal system names unless they are customer-facing
- Technical root cause details such as connection pool exhaustion or cache misses
- Blame or specific engineer names
- Speculation or unconfirmed information
- Overly technical metrics without customer translation

### Status Definitions

- `Investigating`: We are aware of the issue and working to identify the cause
- `Identified`: We know what is wrong and are implementing a fix
- `Monitoring`: A fix is deployed and we are watching to ensure it is working
- `Resolved`: The issue is fixed and the system is stable

### Update Frequency

- Initial acknowledgment: Within 15 to 30 minutes of detection
- Regular updates: Every 30 to 60 minutes during active incidents
- Final resolution notice: Once the system is stable for a sufficient period
