AITHENA - one-click start
=========================
Keep this _clickstart folder INSIDE your AITHENA-live folder (next to the
"server" and "agent" folders).

ON YOUR PC (the server) - just the local test:
  1. Double-click  1-START-SERVER.bat    (leave window open)
  2. Double-click  2-START-AGENT.bat      (leave window open)
  3. Browser: http://localhost:8443/dashboard.html
       bottom Live bar -> Connection -> URL http://localhost:8443, token test123 -> go Live
     You should see DEV-001 / My-PC as LIVE. Done.

TO ADD A FRIEND'S LAPTOP:
  4. Right-click 4-ALLOW-FIREWALL-ADMIN.bat -> "Run as administrator"  (once)
  5. Double-click 3-ENROLL-FRIEND.bat -> type your LAN IP + a name
       (it makes agent-config.<name>.json in the AITHENA-live folder)
  6. Send to the friend, into ONE folder on their PC:
       - agent-config.<name>.json
       - aithena-agent.js            (from the "agent" folder)
       - RUN-ON-FRIEND-PC.bat        (from this _clickstart folder)
     They install Node (nodejs.org, LTS), then double-click RUN-ON-FRIEND-PC.bat.
     They appear as DEV-002 on your dashboard.

Notes: token is "test123" in all scripts. Both PCs must be on the same Wi-Fi.
Never close the server window while testing.
