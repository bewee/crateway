/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::addon_manager::AddonManager;
use crate::macros::send;
use crate::{adapter::Adapter, addon_manager::AddonStarted};
use anyhow::{anyhow, Error};
use futures::{stream::SplitSink, SinkExt};
use log::debug;
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite, WebSocketStream};
use webthings_gateway_ipc_types::{
    Message, MessageBase, PluginRegisterResponseMessageData, Preferences, Units, UserProfile,
};
use xactor::{message, Actor, Context, Handler};

pub struct AddonInstance {
    adapters: HashMap<String, Adapter>,
    stream: SplitSink<WebSocketStream<TcpStream>, tokio_tungstenite::tungstenite::Message>,
}

impl AddonInstance {
    pub fn new(
        stream: SplitSink<WebSocketStream<TcpStream>, tokio_tungstenite::tungstenite::Message>,
    ) -> Self {
        Self {
            adapters: HashMap::new(),
            stream,
        }
    }

    fn get_adapter_mut(&mut self, id: &str) -> Result<&mut Adapter, Error> {
        self.adapters
            .get_mut(id)
            .ok_or_else(|| anyhow!("No adapter with id {} found", id))
    }
}

impl Actor for AddonInstance {}

#[message(result = "Result<(), Error>")]
pub struct Msg(pub Message);

#[async_trait]
impl Handler<Msg> for AddonInstance {
    async fn handle(&mut self, ctx: &mut Context<Self>, Msg(msg): Msg) -> Result<(), Error> {
        debug!("Received {:?}", msg);

        match msg {
            Message::PluginRegisterRequest(msg) => {
                let id = msg.plugin_id();

                send!(AddonManager.AddonStarted(id.to_owned(), ctx.address()))?;

                let response: Message = PluginRegisterResponseMessageData {
                    gateway_version: env!("CARGO_PKG_VERSION").to_owned(),
                    plugin_id: id.to_owned(),
                    preferences: Preferences {
                        language: "en-US".to_owned(),
                        units: Units {
                            temperature: "degree celsius".to_owned(),
                        },
                    },
                    user_profile: UserProfile {
                        addons_dir: "".to_owned(),
                        base_dir: "".to_owned(),
                        config_dir: "".to_owned(),
                        data_dir: "".to_owned(),
                        gateway_dir: "".to_owned(),
                        log_dir: "".to_owned(),
                        media_dir: "".to_owned(),
                    },
                }
                .into();

                debug!("Sending {:?}", &response);
                self.stream
                    .send(tungstenite::Message::Text(serde_json::to_string(
                        &response,
                    )?))
                    .await?;
            }
            Message::AdapterAddedNotification(msg) => {
                let adapter = Adapter::new(msg.data.adapter_id.clone());
                self.adapters.insert(msg.data.adapter_id, adapter);
            }
            Message::DeviceAddedNotification(msg) => {
                let adapter = self.get_adapter_mut(&msg.data.adapter_id)?;
                adapter.add_device(msg.data.device);
            }
            Message::DevicePropertyChangedNotification(msg) => {
                let adapter = self.get_adapter_mut(&msg.data.adapter_id)?;
                adapter.update_property(msg.data.device_id, msg.data.property)?;
            }
            Message::DeviceConnectedStateNotification(msg) => {
                let adapter = self.get_adapter_mut(&msg.data.adapter_id)?;
                adapter.set_connect_state(msg.data.device_id, msg.data.connected)?;
            }
            _ => {}
        };

        Ok(())
    }
}
