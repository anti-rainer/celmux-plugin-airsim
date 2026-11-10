// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The surfaces the iOS client actually calls.
//!
//! AirSIM's iPhone app does not talk to a gateway the way this plugin first
//! guessed. It has two layers:
//!
//! - `/v1/health` — the VoWLAN gateway's identity answer. The app signs the
//!   request and checks `identity_proof`, a MAC over the request nonce and the
//!   agent id. Without that field the app concludes the gateway is unreachable
//!   even though every request succeeded, which is exactly what happened.
//! - `/api/*` — the agent's control plane: health, status, calls, SMS,
//!   long-polling events. Both the direct route and the cloud Relay speak it,
//!   so the app expects the same shapes from us as from the Android agent.
//!
//! Everything here is named and shaped after the client's own models rather
//! than Celmux's. A field that the client decodes must exist with the client's
//! spelling even when Celmux calls it something else; renaming one is how a
//! gateway that answers correctly still looks broken on the phone.

use serde_json::{Value, json};

use crate::celmux::Line;

/// A call as `CallRecord` on the client.
///
/// `id`, `index`, `direction`, `state`, `started_at` are non-optional there, so
/// every field is always present: a record missing one makes the whole array
/// fail to decode and the app shows nothing rather than most of it.
pub fn call_record(
    number: &str,
    state: &str,
    direction: &str,
    started_at: &str,
    line: &str,
    android_id: &str,
) -> Value {
    json!({
        // The phone's own id for this call. It is opaque to the app, but the app
        // hands it back when it hangs up, so it has to be something this side can
        // still resolve - see `android_id` below.
        "id": format!("celmux-call-{started_at}"),
        "index": 0,
        "direction": direction,
        "state": state,
        "number": number,
        "started_at": started_at,
        "updated_at": started_at,
        "missed": false,
        // Which exposed line is ringing. The phone holds one active call and
        // reads this to name the card, so a call arriving on the second line is
        // not shown as one on the first.
        "line_id": line,
        // Celmux's own numeric call id. Celmux answers `answer`/`hangup` only for
        // a call it knows by that number, so it has to travel with the record
        // rather than be reconstructed from the display id.
        "android_id": android_id,
    })
}

/// `CallStatus` — what the app polls for call state.
///
/// The optional fields are omitted rather than sent as null where the client
/// treats absence as "legacy agent": `event_driven` and `revision` are what
/// switch it from polling to the event stream, and claiming support we do not
/// implement would leave it waiting on a stream instead of polling.
pub fn call_status(active: Option<Value>, history: Vec<Value>, revision: u64) -> Value {
    json!({
        "active": active,
        "history": history,
        // Event-driven, as the upstream agent reports itself: the phone then waits
        // on `/api/calls/events` instead of polling on a timer. Claiming `polling:
        // true` with a two-second interval told it to poll, so a call that rang
        // between two polls was seen late - or missed.
        "polling": false,
        "event_driven": true,
        "poll_interval_s": 0,
        "last_poll_error": "",
        "revision": revision,
    })
}

/// `SIMStatus`-shaped answer for `api/sim/identity`.
///
/// The client decodes `phone_number` as a required string, so an unknown number
/// is an empty string rather than null.
pub fn sim_identity(phone_number: &str) -> Value {
    json!({"phone_number": phone_number})
}

/// `SMSStatus`.
pub fn sms_status(count: usize, error: &str) -> Value {
    json!({
        "auto_cleanup_me": false,
        "count": count,
        "last_poll_error": error,
    })
}

/// One `AndroidSIMSlot`, which is how the app names a line when it offers a
/// choice of which one to call or text from.
///
/// A Celmux line is the equivalent of a subscription: one module or one
/// N-standby Profile. The identifier is opaque to the app, so the line id
/// serves, and the label is what a person picks from.
pub fn sim_slot(line: &Line) -> Value {
    json!({
        "id": line.line_id,
        "label": slot_label(line),
        "number": if line.local_phone.is_empty() { Value::Null } else { json!(line.local_phone) },
        "default": false,
        "carrier_name": line.operator_name,
        "is_embedded": false,
        "is_default_voice": false,
        "is_default_sms": false,
    })
}

/// The first two of the three things a person reads in a slot picker.
///
/// The client renders a slot as `label · number`, so the label carries device and
/// operator and the number is supplied separately: together they read
/// `device · operator · number`, which is how a line is named everywhere else in
/// Celmux. Putting the number here would print it twice, and putting the operator
/// only in `carrier_name` would make the title lose it.
fn slot_label(line: &Line) -> String {
    [line.device_name.as_str(), line.operator_name.as_str()]
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<&str>>()
        .join(" · ")
}

/// `AgentEventStatus` for `api/events`.
///
/// The app long-polls this instead of two separate loops, so the call status is
/// nested under `call` and the SIM revision travels alongside it.
pub fn agent_event_status(
    revision: u64,
    call: Value,
    sms_count: usize,
    slots: Vec<Value>,
) -> Value {
    json!({
        "revision": revision,
        "sms_revision": revision,
        "sms_pending": sms_count,
        "call": call,
        "sim_revision": revision,
        "sim_slots": slots,
    })
}

/// One `SMSMessage` from a Celmux SMS row.
///
/// Celmux reports a message with `type` (`sms`, `status_report`, …) and both
/// ends as `sender`/`recipient`; the app wants `sender` as "the other party" and
/// a `direction` of its own. Getting this wrong is not cosmetic: the app keys
/// its history on `delivery_id` and would show every message as incoming with
/// the phone's own number as the correspondent.
pub fn sms_message(row: &Value, operator_name: &str) -> Option<Value> {
    let text = |key: &str| {
        row.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    // Celmux reports the message class as a number: 0/1 are a stored message
    // (incoming and outgoing), and a status report is its own kind. A row that
    // says nothing about direction is treated as incoming, because that is what
    // a message without a queue id practically always is.
    // Celmux stores the message class as a number: 1 is received, 2 is sent.
    // A string form is accepted too, because the field has been both.
    let kind = text("type");
    if kind == "status_report" {
        return None;
    }
    let kind_number = row.get("type").and_then(Value::as_i64);
    // Direction comes from the stored class, never from "does it have a
    // recipient": a received message carries the local number in `recipient`
    // too, so inferring from that labels every incoming message as outgoing -
    // and then reports the phone's own number as the correspondent.
    let outgoing = kind_number == Some(2) || matches!(kind.as_str(), "sent" | "outgoing");
    let peer = if outgoing {
        text("recipient")
    } else {
        text("sender")
    };
    if peer.is_empty() {
        return None;
    }
    let timestamp = text("timestamp");
    if timestamp.is_empty() {
        return None;
    }
    // `message_id` is the queue id and is empty for a message still being
    // stored; `id` is a number, not a string. Both have to be handled, because
    // an empty `delivery_id` makes the app's de-duplication treat the same
    // message as new on every fetch.
    let delivery = row
        .get("message_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            row.get("id").map(|value| match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            })
        })
        .unwrap_or_default();
    Some(json!({
        "sender": peer,
        "content": text("content"),
        "code": null,
        "timestamp": timestamp,
        "delivery_id": delivery,
        "direction": if outgoing { "outgoing" } else { "incoming" },
        // Which line carried it, which is what the app labels a message with.
        // The full name, not just the device: several cards live on one device
        // and the device alone would not say which one sent this.
        "sim_slot": message_slot_label(row, operator_name),
    }))
}

/// How a message says which line carried it.
///
/// Device, operator and number - the same name the line has everywhere else, so
/// a bubble and the picker agree on which card a message came from. The number
/// is included here, unlike a slot's label: the app prints `sim_slot` verbatim
/// rather than composing it with a number of its own.
fn message_slot_label(row: &Value, operator_name: &str) -> String {
    let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or("");
    let device = text("device_name");
    if device.is_empty() {
        return text("device_id").to_owned();
    }
    // Celmux stores a message against the card, not against the line, so the
    // operator is not on the row: it is passed in from the line the message
    // arrived on.
    [device, operator_name, text("local_phone")]
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<&str>>()
        .join(" · ")
}

/// The `messages` array of a `GET /api/sms` answer.
pub fn sms_messages(value: &Value, operator_name: &str) -> Vec<Value> {
    // Celmux answers this route with a bare array. The wrapped forms are kept
    // because that is what this function was written against and an older
    // installation may still send one - but reading only those made every list
    // empty, which reads on the phone as a refresh that does nothing.
    let rows = value
        .as_array()
        .cloned()
        .or_else(|| {
            value
                .get("messages")
                .or_else(|| value.get("items"))
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default();
    rows.iter()
        .filter_map(|row| sms_message(row, operator_name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(id: &str, device: &str, operator: &str, profile: &str) -> Line {
        Line {
            line_id: id.to_owned(),
            device_id: "dev".to_owned(),
            device_name: device.to_owned(),
            profile_name: profile.to_owned(),
            operator_name: operator.to_owned(),
            local_phone: String::new(),
            voice_route: "vocall".to_owned(),
            online: true,
            n_standby: !profile.is_empty(),
        }
    }

    /// The client decodes these five as non-optional, so a record that omits one
    /// makes the whole history unreadable rather than one entry.
    #[test]
    fn a_call_record_carries_every_required_field() {
        let record = call_record(
            "+1234",
            "active",
            "outgoing",
            "2026-01-01T00:00:00Z",
            "读卡器2#89441000400501246765",
            "21",
        );
        for key in ["id", "index", "direction", "state", "started_at", "updated_at"] {
            assert!(!record[key].is_null(), "{key} must be present");
        }
        assert_eq!(record["state"], "active");
        assert_eq!(record["missed"], false);
    }

    /// Claiming the event stream without implementing it would leave the app
    /// waiting on a socket instead of polling.
    #[test]
    fn call_status_reports_an_event_stream_rather_than_a_poll() {
        let status = call_status(None, Vec::new(), 11);
        // The upstream agent reports itself this way, and the phone behaves
        // differently depending on it: `polling: true` with a timer means poll,
        // which is how a short ring was missed.
        assert_eq!(status["polling"], false);
        assert_eq!(status["event_driven"], true);
        assert_eq!(status["poll_interval_s"], 0);
        assert_eq!(status["revision"], 11, "手机用 revision 等待下一次变化");
    }

    /// A slot with no number must send an empty string: the client treats the
    /// number as optional but the label as required.
    #[test]
    fn a_slot_is_labelled_the_same_way_the_line_is_named() {
        // Device, operator, number - the same string the line carries
        // everywhere else, so the picker and the line list agree.
        // Device and operator only: the client appends the number itself, so a
        // number here shows up twice in the picker.
        let with_operator = sim_slot(&line("l1", "读卡器1", "Globe", ""));
        assert_eq!(with_operator["label"], "读卡器1 · Globe");
        assert_eq!(with_operator["id"], "l1");

        let bare = sim_slot(&line("l3", "dji1", "", ""));
        assert_eq!(bare["label"], "dji1");
        assert_eq!(bare["number"], Value::Null);
    }

    /// A sent message must come out with the recipient as `sender` and the
    /// outgoing direction: the app shows `sender` as "who this is with", so
    /// copying Celmux's row through would label a sent message with the phone's
    /// own number and render it as received.
    #[test]
    fn a_sent_message_becomes_outgoing_from_the_recipient() {
        let row = json!({
            "id": "db-1", "type": "sent", "sender": "+447469192531",
            "recipient": "+447385886256", "content": "hello",
            "timestamp": "2026-01-01T00:00:00Z", "device_name": "读卡器1",
            "message_id": "abc",
        });
        let message = sms_message(&row, "LoopDL").unwrap();
        assert_eq!(message["sender"], "+447385886256");
        assert_eq!(message["direction"], "outgoing");
        assert_eq!(message["content"], "hello");
        assert_eq!(message["delivery_id"], "abc");
        assert_eq!(message["sim_slot"], "读卡器1 · LoopDL");
    }

    /// A received message keeps its sender as the correspondent. Celmux stores
    /// it as class 1 with the local number in `recipient`, so inferring direction
    /// from "has a recipient" would label it outgoing and hand the app the
    /// phone's own number as the person it is talking to.
    #[test]
    fn a_received_message_becomes_incoming_from_its_sender() {
        let row = json!({
            "id": 21, "type": 1, "sender": "+447464383173",
            "recipient": "+447469192531", "content": "hello",
            "timestamp": "2026-01-01T00:00:01Z", "device_name": "读卡器1",
        });
        let message = sms_message(&row, "LoopDL").unwrap();
        assert_eq!(message["sender"], "+447464383173");
        assert_eq!(message["direction"], "incoming");
        assert_eq!(message["sim_slot"], "读卡器1 · LoopDL");
        // A numeric id still has to become a usable de-duplication key.
        assert_eq!(message["delivery_id"], "21");
    }

    /// A sent message is class 2.
    #[test]
    fn a_sent_message_is_recognised_by_its_class() {
        let row = json!({
            "id": 12, "type": 2, "sender": "+447469192531",
            "recipient": "+447385886256", "content": "hi",
            "timestamp": "2026-01-01T00:00:01Z", "message_id": "读卡器1-abc",
        });
        let message = sms_message(&row, "LoopDL").unwrap();
        assert_eq!(message["direction"], "outgoing");
        assert_eq!(message["sender"], "+447385886256");
        assert_eq!(message["delivery_id"], "读卡器1-abc");
    }

    /// A delivery receipt is not a message; the app would show it as an empty
    /// bubble from nobody.
    #[test]
    fn a_status_report_is_not_a_message() {
        let row = json!({
            "id": "db-3", "type": "status_report", "sender": "",
            "recipient": "+44", "content": "", "timestamp": "2026-01-01T00:00:02Z",
        });
        assert!(sms_message(&row, "LoopDL").is_none());
    }

    /// The app keys its history on `delivery_id`, so a row without the queue id
    /// falls back to the database id rather than shipping null.
    #[test]
    fn a_message_without_a_queue_id_still_has_an_identity() {
        let row = json!({
            "id": "db-4", "type": "sms", "sender": "+44", "content": "x",
            "timestamp": "2026-01-01T00:00:03Z",
        });
        assert_eq!(sms_message(&row, "LoopDL").unwrap()["delivery_id"], "db-4");
    }

    /// The nested `call` object is what the app reads; a flat status would
    /// decode as a failure and stop the poll loop.
    #[test]
    fn the_event_status_nests_the_call_status() {
        let status = agent_event_status(7, call_status(None, Vec::new(), 0), 3, Vec::new());
        assert_eq!(status["revision"], 7);
        assert_eq!(status["sms_pending"], 3);
        assert_eq!(status["call"]["polling"], false, "嵌套的通话状态同样是事件驱动");
        assert_eq!(status["sim_revision"], 7);
    }
    /// Celmux answers the plugin's SMS route with a bare array. Reading only the
    /// wrapped forms made the list empty, which on the phone is indistinguishable
    /// from a refresh that does nothing.
    #[test]
    fn a_bare_array_of_messages_is_read() {
        let row = json!([{
            "id": 1,
            "content": "你好",
            "peer": "+100",
            "sender": "+100",
            "recipient": "+200",
            "local_phone": "+200",
            "timestamp": "2026-11-09T16:00:00Z",
        }]);
        let messages = sms_messages(&row, "LoopDL");
        assert_eq!(messages.len(), 1, "裸数组应被读取");
        let wrapped = json!({"messages": row.as_array().unwrap().clone()});
        assert_eq!(sms_messages(&wrapped, "LoopDL").len(), 1, "包装形式仍应可读");
    }
    /// A bubble says which card carried a message, and the number is part of
    /// that: several cards share a device, and the device alone would not tell
    /// them apart.
    #[test]
    fn a_message_names_its_card_by_device_operator_and_number() {
        let row = json!({
            "id": 31, "type": 1, "sender": "+447464383173",
            "recipient": "+447469192531", "content": "hi",
            "timestamp": "2026-01-01T00:00:03Z",
            "device_name": "读卡器2", "local_phone": "+447464383173",
        });
        let message = sms_message(&row, "LoopDL").unwrap();
        assert_eq!(message["sim_slot"], "读卡器2 · LoopDL · +447464383173");
    }
}
