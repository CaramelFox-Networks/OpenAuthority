/*
 * OpenAuthority
 * Copyright (C) 2026 CaramelFox Networks LLC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { generateUUID } from "../utils";
import { pemToDer, extractCN } from "./parsing";

export function generateMobileConfig(certificates: Array<{ pem_data: string; subject: string; fingerprint_sha256: string }>): string {
  const profileUUID = generateUUID('openauthority-trust-store-profile');

  const certPayloads = certificates.map((cert, index) => {
    const derData = pemToDer(cert.pem_data);
    const base64Data = btoa(String.fromCharCode(...derData));
    const formattedBase64 = base64Data.match(/.{1,52}/g)?.join('\n') || base64Data;
    const certUUID = generateUUID(cert.fingerprint_sha256);
    const certName = extractCN(cert.subject);

    return `
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>${certName}.cer</string>
			<key>PayloadContent</key>
			<data>
${formattedBase64}
			</data>
			<key>PayloadDescription</key>
			<string>Adds a CA root certificate from OpenAuthority Trust Store</string>
			<key>PayloadDisplayName</key>
			<string>${certName}</string>
			<key>PayloadIdentifier</key>
			<string>org.openauthority.truststore.cert.${index}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>${certUUID}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>`;
  }).join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>${certPayloads}
	</array>
	<key>PayloadDescription</key>
	<string>Installs the OpenAuthority Trust Store CA certificates.</string>
	<key>PayloadDisplayName</key>
	<string>OpenAuthority Trust Store</string>
	<key>PayloadIdentifier</key>
	<string>org.openauthority.truststore</string>
	<key>PayloadOrganization</key>
	<string>OpenAuthority Project</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>${profileUUID}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>ConsentText</key>
	<dict>
		<key>default</key>
		<string>This profile installs ${certificates.length} CA certificate(s) from the OpenAuthority Trust Store.</string>
	</dict>
</dict>
</plist>`;
}