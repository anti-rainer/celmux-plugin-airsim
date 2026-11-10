# celmux-plugin-airsim

Use an AirSIM iOS client as a handset for the VoWiFi/VoLTE lines managed by
Celmux.

## What it does

Celmux runs the SIM cards, the IMS registrations and the calls. This plugin
exposes those lines to an AirSIM phone, so the phone behaves like a handset
attached to the gateway:

- Browse the lines the gateway offers and choose the one to call from.
- Place, answer, reject and hang up calls, with the audio carried to the phone.
- Send and receive SMS on any line, with the sender's number preserved.
- Receive incoming call and message notifications while the app is in the
  background.

One gateway serves one phone. Several cards behind that gateway are presented as
a list of lines, so switching cards does not mean re-pairing.

## How it fits together

```
AirSIM iOS  ──local network──>  celmux-plugin-airsim  ──plugin API──>  Celmux
                                (separate process)                    (gateway)
```

The plugin holds no card state of its own. Every question about lines, calls and
messages is answered by Celmux, which stays the single source of truth.

## Requirements

- A Celmux installation with at least one VoWiFi or VoLTE line.
- The AirSIM iOS client on the same local network as the gateway.

## Setup

Install the plugin from Celmux, enable it, grant the permissions it asks for,
then pair the phone from the plugin's own page. Pairing links a particular phone
to a particular gateway; pairing again replaces the previous phone rather than
adding a second one.

## Notes

- Calls and messages work entirely over the local network. Nothing about a call
  depends on a cloud service.
- Lines can be assigned by hand, or followed live as Celmux gains and loses them:
  a reader plugged in, a profile switched in N-standby, a tunnel coming up.
- Each line's own automatic-answer setting belongs to the operator. The plugin
  can take incoming calls over so the phone rings for them, and releasing that
  leaves the setting exactly as the operator left it.

## License

PolyForm Noncommercial 1.0.0
