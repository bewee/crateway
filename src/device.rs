/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use webthings_gateway_ipc_types::Device as DeviceDescription;

pub struct Device {
    description: DeviceDescription,
}

impl Device {
    pub fn new(description: DeviceDescription) -> Self {
        Self { description }
    }

    pub fn update(&mut self, description: DeviceDescription) {
        let id = description.id.clone();
        self.description = description;
        info!("Device updated {}", id)
    }
}