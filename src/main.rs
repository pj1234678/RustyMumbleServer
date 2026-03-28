use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use rand::Rng;
use rustls_pemfile::{certs, private_key};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::rustls::{pki_types::CertificateDer, pki_types::PrivateKeyDer, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{Decoder, Encoder, Framed};
 use std::hint::black_box;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum MessageType {
    Version = 0,
    UdpTunnel = 1,
    Authenticate = 2,
    Ping = 3,
    Reject = 4,
    ServerSync = 5,
    ChannelRemove = 6,
    ChannelState = 7,
    UserRemove = 8,
    UserState = 9,
    BanList = 10,
    TextMessage = 11,
    PermissionDenied = 12,
    Acl = 13,
    QueryUsers = 14,
    CryptSetup = 15,
    ContextActionModify = 16,
    ContextAction = 17,
    UserList = 18,
    VoiceTarget = 19,
    PermissionQuery = 20,
    CodecVersion = 21,
    UserStats = 22,
    RequestBlob = 23,
    ServerConfig = 24,
    SuggestConfig = 25,
}

impl TryFrom<u16> for MessageType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Version),
            1 => Ok(MessageType::UdpTunnel),
            2 => Ok(MessageType::Authenticate),
            3 => Ok(MessageType::Ping),
            4 => Ok(MessageType::Reject),
            5 => Ok(MessageType::ServerSync),
            6 => Ok(MessageType::ChannelRemove),
            7 => Ok(MessageType::ChannelState),
            8 => Ok(MessageType::UserRemove),
            9 => Ok(MessageType::UserState),
            10 => Ok(MessageType::BanList),
            11 => Ok(MessageType::TextMessage),
            12 => Ok(MessageType::PermissionDenied),
            13 => Ok(MessageType::Acl),
            14 => Ok(MessageType::QueryUsers),
            15 => Ok(MessageType::CryptSetup),
            16 => Ok(MessageType::ContextActionModify),
            17 => Ok(MessageType::ContextAction),
            18 => Ok(MessageType::UserList),
            19 => Ok(MessageType::VoiceTarget),
            20 => Ok(MessageType::PermissionQuery),
            21 => Ok(MessageType::CodecVersion),
            22 => Ok(MessageType::UserStats),
            23 => Ok(MessageType::RequestBlob),
            24 => Ok(MessageType::ServerConfig),
            25 => Ok(MessageType::SuggestConfig),
            _ => Err(anyhow!("Unknown message type: {}", value)),
        }
    }
}

struct MumbleCodec;

impl Decoder for MumbleCodec {
    type Item = (u16, Bytes);
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < 6 {
            return Ok(None);
        }
        let mut header = &src[..6];
        let msg_type_raw = header.get_u16();
        let length = header.get_u32() as usize;

	if length > 64 * 1024 {
    		return Err(anyhow::anyhow!("Payload too large"));
	}
        if src.len() < 6 + length {
            return Ok(None);
        }

        src.advance(6);
        let payload = src.split_to(length).freeze();
        Ok(Some((msg_type_raw, payload)))
    }
}

impl Encoder<(MessageType, Bytes)> for MumbleCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: (MessageType, Bytes), dst: &mut BytesMut) -> Result<()> {
        dst.reserve(6 + item.1.len());
        dst.put_u16(item.0 as u16);
        dst.put_u32(item.1.len() as u32);
        dst.put(item.1);
        Ok(())
    }
}

mod protobuf {
    use super::*;

    pub fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut result = Vec::new();
        while value > 0x7F {
            result.push(((value & 0x7F) | 0x80) as u8);
            value >>= 7;
        }
        result.push((value & 0x7F) as u8);
        result
    }

pub fn decode_varint(data: &[u8]) -> Result<(u64, usize)> {
    let mut result = 0;
    let mut shift = 0;
    let mut pos = 0;
    while pos < data.len() {
        // FIX: Prevent the shift from overflowing and panicking Rust
        if shift >= 64 {
            return Err(anyhow!("Malformed varint: shift overflow"));
        }

        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Ok((result, pos));
        }
        shift += 7;
    }
    Err(anyhow!("Truncated varint"))
}
    pub fn encode_field(field_num: u32, wire_type: u8, mut payload: Vec<u8>) -> Vec<u8> {
        let mut result = Vec::new();
        let tag = (field_num << 3) | (wire_type as u32);
        result.append(&mut encode_varint(tag as u64));
        result.append(&mut payload);
        result
    }

    pub fn encode_uint32(field_num: u32, value: u32) -> Vec<u8> {
        encode_field(field_num, 0, encode_varint(value as u64))
    }

    pub fn encode_bool(field_num: u32, value: bool) -> Vec<u8> {
        encode_field(field_num, 0, encode_varint(if value { 1 } else { 0 }))
    }

    pub fn encode_string(field_num: u32, value: &str) -> Vec<u8> {
        if value.is_empty() {
            return Vec::new();
        }
        let encoded = value.as_bytes().to_vec();
        let mut len_encoded = encode_varint(encoded.len() as u64);
        len_encoded.extend(encoded);
        encode_field(field_num, 2, len_encoded)
    }

    pub fn encode_bytes(field_num: u32, value: &[u8]) -> Vec<u8> {
        if value.is_empty() {
            return Vec::new();
        }
        let mut len_encoded = encode_varint(value.len() as u64);
        len_encoded.extend(value);
        encode_field(field_num, 2, len_encoded)
    }

    pub struct Field {
        pub num: u64,
        pub wire_type: u8,
        pub value: Vec<u8>,
        pub varint_val: Option<u64>,
    }

    pub fn decode_field(data: &[u8]) -> Result<Option<(Field, usize)>> {
        if data.is_empty() {
            return Ok(None);
        }
        let (tag_value, mut offset) = decode_varint(data)?;
        let field_num = tag_value >> 3;
        let wire_type = (tag_value & 0x7) as u8;

        let (value, varint_val) = match wire_type {
            0 => {
                let (val, len) = decode_varint(&data[offset..])?;
                offset += len;
                let val_bytes = data[offset - len..offset].to_vec();
                (val_bytes, Some(val))
            }
            2 => {
                let (length, len) = decode_varint(&data[offset..])?;
                offset += len;
                let length_usize = length as usize;
                let end = offset.checked_add(length_usize).ok_or_else(|| anyhow!("Field length overflow"))?;
                if end > data.len() {
                    return Err(anyhow!("Truncated field"));
                }
                let val = data[offset..end].to_vec();
                offset = end;
                (val, None)
            }
            5 => {
                let end = offset.checked_add(4).ok_or_else(|| anyhow!("32-bit field overflow"))?;
                if end > data.len() {
                    return Err(anyhow!("Truncated 32-bit field"));
                }
                let val = data[offset..end].to_vec();
                offset = end;
                (val, None)
            }
            _ => return Err(anyhow!("Unsupported wire type: {}", wire_type)),
        };

        Ok(Some((
            Field {
                num: field_num,
                wire_type,
                value,
                varint_val,
            },
            offset,
        )))
    }
}

mod messages {
    use super::*;
    use protobuf::*;
    use std::str;
      
    #[derive(Debug, Default)]
    pub struct Version {
        pub version: u32,
        pub release: String,
        pub os: String,
        pub os_version: String,
    }

    impl Version {
        pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            if self.version > 0 {
                result.append(&mut encode_uint32(1, self.version));
            }
            if !self.release.is_empty() {
                result.append(&mut encode_string(2, &self.release));
            }
            if !self.os.is_empty() {
                result.append(&mut encode_string(3, &self.os));
            }
            if !self.os_version.is_empty() {
                result.append(&mut encode_string(4, &self.os_version));
            }
            result
        }

        pub fn decode(data: &[u8]) -> Result<Self> {
            let mut msg = Self::default();
            let mut offset = 0;
            while let Some((field, new_offset)) = decode_field(&data[offset..])? {
                offset += new_offset;
                match field.num {
                    1 => msg.version = field.varint_val.unwrap_or(0) as u32,
                    2 => msg.release = str::from_utf8(&field.value)?.to_string(),
                    3 => msg.os = str::from_utf8(&field.value)?.to_string(),
                    4 => msg.os_version = str::from_utf8(&field.value)?.to_string(),
                    _ => {}
                }
            }
            Ok(msg)
        }
    }

    #[derive(Debug, Default)]
    pub struct Authenticate {
        pub username: String,
        pub password: String,
        pub tokens: Vec<String>,
        pub celt_versions: Vec<i32>,
        pub opus: bool,
    }

    impl Authenticate {
        pub fn decode(data: &[u8]) -> Result<Self> {
            let mut msg = Self::default();
            let mut offset = 0;
            while let Some((field, new_offset)) = decode_field(&data[offset..])? {
                offset += new_offset;
                match field.num {
                    1 => {
                        if field.value.len() > 64 {
                            return Err(anyhow::anyhow!("Username too long"));
                        }
                        msg.username = std::str::from_utf8(&field.value)?.to_string();
                    },
                    2 => {
                        if field.value.len() > 128 {
                            return Err(anyhow::anyhow!("Password too long"));
                        }
                        msg.password = std::str::from_utf8(&field.value)?.to_string();
                    },
                    3 => msg.tokens.push(std::str::from_utf8(&field.value)?.to_string()),
                    4 => msg.celt_versions.push(field.varint_val.unwrap_or(0) as i32),
                    5 => msg.opus = field.varint_val.unwrap_or(0) != 0,
                    _ => {}
                }
            }
            Ok(msg)
        }
    }
      
    #[derive(Default)]
    pub struct CryptSetup {
        pub key: Vec<u8>,
        pub client_nonce: Vec<u8>,
        pub server_nonce: Vec<u8>,
    }

    impl CryptSetup {
        pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            if !self.key.is_empty() {
                result.append(&mut encode_bytes(1, &self.key));
            }
            if !self.client_nonce.is_empty() {
                result.append(&mut encode_bytes(2, &self.client_nonce));
            }
            if !self.server_nonce.is_empty() {
                result.append(&mut encode_bytes(3, &self.server_nonce));
            }
            result
        }
    }

    pub struct ChannelState {
        pub channel_id: u32,
        pub parent: Option<u32>,
        pub name: String,
        pub links: Vec<u32>,
        pub description: String,
        pub temporary: bool,
        pub position: u32,
    }

    impl ChannelState {
        pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            result.append(&mut encode_uint32(1, self.channel_id));
            if let Some(parent) = self.parent {
                result.append(&mut encode_uint32(2, parent));
            }
            if !self.name.is_empty() {
                result.append(&mut encode_string(3, &self.name));
            }
            for link in &self.links {
                result.append(&mut encode_uint32(4, *link));
            }
            if !self.description.is_empty() {
                result.append(&mut encode_string(5, &self.description));
            }
            if self.temporary {
                result.append(&mut encode_bool(7, self.temporary));
            }
            if self.position > 0 {
                result.append(&mut encode_uint32(9, self.position));
            }
            result
        }
    }

    #[derive(Default)]
    pub struct UserState {
        pub session: u32,
        pub actor: Option<u32>,
        pub name: String,
        pub channel_id: u32,
        pub mute: Option<bool>,
        pub deaf: Option<bool>,
        pub suppress: Option<bool>,
        pub self_mute: Option<bool>,
        pub self_deaf: Option<bool>,
        pub comment: String,
        pub hash: String,
        pub priority_speaker: Option<bool>,
        pub recording: Option<bool>,
    }

    impl UserState {
        pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            result.append(&mut encode_uint32(1, self.session));
            if let Some(actor) = self.actor {
                result.append(&mut encode_uint32(2, actor));
            }
            if !self.name.is_empty() {
                result.append(&mut encode_string(3, &self.name));
            }
            result.append(&mut encode_uint32(5, self.channel_id));
            
            if let Some(val) = self.mute { result.append(&mut encode_bool(6, val)); }
            if let Some(val) = self.deaf { result.append(&mut encode_bool(7, val)); }
            if let Some(val) = self.suppress { result.append(&mut encode_bool(8, val)); }
            if let Some(val) = self.self_mute { result.append(&mut encode_bool(9, val)); }
            if let Some(val) = self.self_deaf { result.append(&mut encode_bool(10, val)); }
            
            if !self.comment.is_empty() {
                result.append(&mut encode_string(14, &self.comment));
            }
            if !self.hash.is_empty() {
                result.append(&mut encode_string(15, &self.hash));
            }
            
            if let Some(val) = self.priority_speaker { result.append(&mut encode_bool(17, val)); }
            if let Some(val) = self.recording { result.append(&mut encode_bool(18, val)); }
            
            result
        }

        pub fn decode_changes(data: &[u8]) -> Result<HashMap<String, u64>> {
             let mut changes = HashMap::new();
             let mut offset = 0;
             while let Some((field, new_offset)) = decode_field(&data[offset..])? {
                 offset += new_offset;
                 if let Some(varint_val) = field.varint_val {
                    let key = match field.num {
                        5 => "channel_id",
                        6 => "mute",
                        7 => "deaf",
                        8 => "suppress",
                        9 => "self_mute",
                        10 => "self_deaf",
                        17 => "priority_speaker",
                        18 => "recording",
                        _ => continue,
                    };
                    changes.insert(key.to_string(), varint_val);
                 }
             }
             Ok(changes)
        }
    }

    pub struct ServerSync {
        pub session: u32,
        pub max_bandwidth: u32,
        pub welcome_text: String,
        pub permissions: u64,
    }
      
    impl ServerSync {
        pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            result.append(&mut encode_uint32(1, self.session));
            if self.max_bandwidth > 0 {
                result.append(&mut encode_uint32(2, self.max_bandwidth));
            }
            if !self.welcome_text.is_empty() {
                result.append(&mut encode_string(3, &self.welcome_text));
            }
            if self.permissions > 0 {
                result.append(&mut encode_field(4, 0, encode_varint(self.permissions)));
            }
            result
        }
    }

    #[derive(Debug, Default)]
    pub struct Ping {
        pub timestamp: u64,
        pub good: u32,
        pub late: u32,
        pub lost: u32,
        pub resync: u32,
        pub udp_packets: u32,
        pub tcp_packets: u32,
        pub udp_ping_avg: f32,
        pub udp_ping_var: f32,
        pub tcp_ping_avg: f32,
        pub tcp_ping_var: f32,
    }

    impl Ping {
        pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            if self.timestamp > 0 {
                result.append(&mut encode_field(1, 0, encode_varint(self.timestamp)));
            }
            result
        }

        pub fn decode(data: &[u8]) -> Result<Self> {
            let mut msg = Self::default();
            let mut offset = 0;
            while let Some((field, new_offset)) = decode_field(&data[offset..])? {
                offset += new_offset;
                match field.num {
                    1 => msg.timestamp = field.varint_val.unwrap_or(0),
                    2 => msg.good = field.varint_val.unwrap_or(0) as u32,
                    3 => msg.late = field.varint_val.unwrap_or(0) as u32,
                    4 => msg.lost = field.varint_val.unwrap_or(0) as u32,
                    5 => msg.resync = field.varint_val.unwrap_or(0) as u32,
                    6 => msg.udp_packets = field.varint_val.unwrap_or(0) as u32,
                    7 => msg.tcp_packets = field.varint_val.unwrap_or(0) as u32,
                    8 => if field.value.len() >= 4 { msg.udp_ping_avg = f32::from_le_bytes(field.value[..4].try_into()?) },
                    9 => if field.value.len() >= 4 { msg.udp_ping_var = f32::from_le_bytes(field.value[..4].try_into()?) },
                    10 => if field.value.len() >= 4 { msg.tcp_ping_avg = f32::from_le_bytes(field.value[..4].try_into()?) },
                    11 => if field.value.len() >= 4 { msg.tcp_ping_var = f32::from_le_bytes(field.value[..4].try_into()?) },
                    _ => {}
                }
            }
            Ok(msg)
        }
    }
      
    pub struct Reject {
        pub reject_type: u32,
        pub reason: String,
    }

    impl Reject {
        pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            result.append(&mut encode_uint32(1, self.reject_type));
            if !self.reason.is_empty() {
                result.append(&mut encode_string(2, &self.reason));
            }
            result
        }
    }

    #[derive(Debug, Default)]
    pub struct PermissionQuery {
        pub channel_id: u32,
        pub permissions: u32,
        pub flush: bool,
    }

    impl PermissionQuery {
         pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            result.append(&mut encode_uint32(1, self.channel_id));
            if self.permissions > 0 {
                result.append(&mut encode_uint32(2, self.permissions));
            }
            if self.flush {
                result.append(&mut encode_bool(3, self.flush));
            }
            result
        }
        pub fn decode(data: &[u8]) -> Result<Self> {
            let mut msg = Self::default();
            let mut offset = 0;
            while let Some((field, new_offset)) = decode_field(&data[offset..])? {
                offset += new_offset;
                match field.num {
                    1 => msg.channel_id = field.varint_val.unwrap_or(0) as u32,
                    _ => {}
                }
            }
            Ok(msg)
        }
    }

    #[derive(Debug, Default)]
    pub struct CodecVersion {
        pub alpha: i32,
        pub beta: i32,
        pub prefer_alpha: bool,
        pub opus: bool,
    }

    impl CodecVersion {
        pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            result.append(&mut encode_field(1, 0, encode_varint(self.alpha as u64)));
            result.append(&mut encode_field(2, 0, encode_varint(self.beta as u64)));
            result.append(&mut encode_bool(3, self.prefer_alpha));
            result.append(&mut encode_bool(4, self.opus));
            result
        }
        pub fn decode(data: &[u8]) -> Result<Self> {
            let mut msg = Self::default();
            let mut offset = 0;
            while let Some((field, new_offset)) = decode_field(&data[offset..])? {
                offset += new_offset;
                match field.num {
                    1 => msg.alpha = field.varint_val.unwrap_or(0) as i32,
                    2 => msg.beta = field.varint_val.unwrap_or(0) as i32,
                    3 => msg.prefer_alpha = field.varint_val.unwrap_or(0) != 0,
                    4 => msg.opus = field.varint_val.unwrap_or(0) != 0,
                    _ => {}
                }
            }
            Ok(msg)
        }
    }
      
    #[derive(Debug, Default)]
    pub struct TextMessage {
        pub actor: u32,
        pub session: Vec<u32>,
        pub channel_id: Vec<u32>,
        pub tree_id: Vec<u32>,
        pub message: String,
    }

    impl TextMessage {
        pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            result.append(&mut encode_uint32(1, self.actor));
            for session in &self.session {
                result.append(&mut encode_uint32(2, *session));
            }
            for channel_id in &self.channel_id {
                result.append(&mut encode_uint32(3, *channel_id));
            }
            for tree_id in &self.tree_id {
                result.append(&mut encode_uint32(4, *tree_id));
            }
            result.append(&mut encode_string(5, &self.message));
            result
        }
        pub fn decode(data: &[u8]) -> Result<Self> {
            let mut msg = Self::default();
            let mut offset = 0;
            while let Some((field, new_offset)) = decode_field(&data[offset..])? {
                offset += new_offset;
                match field.num {
                    1 => msg.actor = field.varint_val.unwrap_or(0) as u32,
                    2 => msg.session.push(field.varint_val.unwrap_or(0) as u32),
                    3 => msg.channel_id.push(field.varint_val.unwrap_or(0) as u32),
                    4 => msg.tree_id.push(field.varint_val.unwrap_or(0) as u32),
                    5 => msg.message = str::from_utf8(&field.value)?.to_string(),
                    _ => {}
                }
            }
            Ok(msg)
        }
    }

    #[derive(Default)]
    pub struct UserStats {
        pub session: u32,
    }

    impl UserStats {
         pub fn encode(&self) -> Vec<u8> {
            let mut result = Vec::new();
            result.append(&mut encode_uint32(1, self.session));
            result.append(&mut encode_bool(2, false));
            result
        }
        pub fn decode(data: &[u8]) -> Result<Self> {
            let mut msg = Self::default();
            let offset = 0;
            if let Some((field, _)) = decode_field(&data[offset..])? {
                if field.num == 1 {
                    msg.session = field.varint_val.unwrap_or(0) as u32;
                }
            }
            Ok(msg)
        }
    }
      
    pub struct UserRemove {
        pub session: u32,
    }
      
    impl UserRemove {
        pub fn encode(&self) -> Vec<u8> {
            encode_uint32(1, self.session)
        }
    }
}

#[derive(Debug, Clone)]
struct Channel {
    channel_id: u32,
    parent_id: i32,
    name: String,
    description: String,
    temporary: bool,
    position: u32,
    links: HashSet<u32>,
    users: HashSet<u32>,
}

#[derive(Debug, Clone)]
struct User {
    session: u32,
    name: String,
    channel_id: u32,
    mute: bool,
    deaf: bool,
    suppress: bool,
    self_mute: bool,
    self_deaf: bool,
    priority_speaker: bool,
    recording: bool,
}

type ClientSender = mpsc::Sender<(MessageType, Bytes)>;

struct MumbleServer {
    channels: DashMap<u32, Channel>,
    users: DashMap<u32, User>,
    client_handlers: DashMap<u32, ClientSender>,
    next_session_id: AtomicU32,
    next_channel_id: AtomicU32,
    version: u32,
    release: String,
    password: Option<String>,
}

impl MumbleServer {
    fn new(password: Option<String>) -> Self {
        let server = MumbleServer {
            channels: DashMap::new(),
            users: DashMap::new(),
            client_handlers: DashMap::new(),
            next_session_id: AtomicU32::new(1),
            next_channel_id: AtomicU32::new(1),
            version: (1 << 16) | (4 << 8) | 0,
            release: "1.4.0".to_string(),
            password,
        };
        info!("Mumble Server initialized - Version {}", server.release);
        if server.password.is_some() {
            info!("Server password protection is ENABLED");
        } else {
            warn!("Server password protection is DISABLED");
        }
        server
    }
      
    async fn init_root_channel(&self) {
        let root = Channel {
            channel_id: 0,
            parent_id: -1,
            name: "Root".to_string(),
            description: "Root Channel".to_string(),
            temporary: false,
            position: 0,
            links: HashSet::new(),
            users: HashSet::new(),
        };
        self.channels.insert(0, root);
        debug!("Root channel created");
    }

    async fn create_channel(&self, name: &str, parent_id: u32) {
        let channel_id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);
        let channel = Channel {
            channel_id,
            parent_id: parent_id as i32,
            name: name.to_string(),
            description: "".to_string(),
            temporary: false,
            position: 0,
            links: HashSet::new(),
            users: HashSet::new(),
        };
        debug!("Channel created: {} (ID: {})", name, channel_id);
        self.channels.insert(channel_id, channel);
    }
      
    fn allocate_session(&self) -> u32 {
        self.next_session_id.fetch_add(1, Ordering::SeqCst)
    }

    async fn broadcast_message(
        &self,
        msg_type: MessageType,
        payload: Bytes,
        exclude_session: Option<u32>,
    ) {
        let senders: Vec<ClientSender> = self.client_handlers
            .iter()
            .filter(|kv| Some(*kv.key()) != exclude_session)
            .map(|kv| kv.value().clone())
            .collect();

        for tx in senders {
            if let Err(e) = tx.send((msg_type, payload.clone())).await {
                debug!("Failed to broadcast: {}", e);
            }
        }
    }

    async fn start(self: Arc<Self>, addr: &str, certfile: &str, keyfile: &str) -> Result<()> {
        let certs = load_certs(certfile)?;
        let key = load_private_key(keyfile)?;
          
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow!("Failed to create TLS config: {}", e))?;
          
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(addr).await?;
          
        info!("Server listening on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let server_arc = self.clone();

            tokio::spawn(async move {
                info!("New connection from {}", peer_addr);
                let stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("TLS handshake error: {}", e);
                        return;
                    }
                };

                let mut handler = ClientHandler::new(server_arc, peer_addr);
                if let Err(e) = handler.handle(stream).await {
                    debug!("Client handler error for {}: {}", peer_addr, e);
                }
            });
        }
    }
}

struct ClientHandler {
    server: Arc<MumbleServer>,
    addr: SocketAddr,
    session_id: Option<u32>,
    last_ping: Arc<tokio::sync::RwLock<SystemTime>>,
    tx: Option<ClientSender>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl ClientHandler {
    fn new(server: Arc<MumbleServer>, addr: SocketAddr) -> Self {
        ClientHandler {
            server,
            addr,
            session_id: None,
            last_ping: Arc::new(tokio::sync::RwLock::new(SystemTime::now())),
            tx: None,
            shutdown_tx: None,
        }
    }

    async fn handle(&mut self, stream: tokio_rustls::server::TlsStream<TcpStream>) -> Result<()> {
        let framed = Framed::new(stream, MumbleCodec);
        let (mut writer, mut reader) = framed.split();
        
        let (tx, mut rx) = mpsc::channel::<(MessageType, Bytes)>(100);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
          
        self.tx = Some(tx.clone());
        self.shutdown_tx = Some(shutdown_tx);
          
        let writer_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                 let write_result = timeout(Duration::from_secs(5), writer.send(msg)).await;
                 match write_result {
                    Ok(Ok(_)) => {},
                    Ok(Err(e)) => {
                        debug!("Write error: {}", e);
                        break;
                    }
                    Err(_) => {
                        debug!("Write timeout, client stall.");
                        break;
                    }
                 }
            }
        });

        debug!("Starting connection handling for {}", self.addr);

        loop {
            tokio::select! {
                result = reader.next() => {
                    match result {
                        Some(Ok((msg_type_raw, payload))) => {
                            let msg_type = match MessageType::try_from(msg_type_raw) {
                                Ok(t) => t,
                                Err(_) => {
                                    warn!("Received unknown message type: {}", msg_type_raw);
                                    continue;
                                }
                            };
                            
                            if msg_type != MessageType::UdpTunnel && msg_type != MessageType::Ping {
                                debug!("Received message: {:?} (length: {})", msg_type, payload.len());
                            }
                            
                            if let Err(e) = self.handle_message(msg_type, payload).await {
                                error!("Error handling message: {}", e);
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            error!("Read error: {}", e);
                            break;
                        }
                        None => {
                            info!("Client disconnected: {}", self.addr);
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received for {}", self.addr);
                    break;
                }
            }
            
            if self.tx.as_ref().map(|x| x.is_closed()).unwrap_or(true) {
                break;
            }
        }

        self.cleanup().await;
        writer_task.abort();
        Ok(())
    }

    async fn cleanup(&mut self) {
        let session_id = match self.session_id {
            Some(id) => id,
            None => return,
        };

        info!("Cleaning up connection: {} (session: {})", self.addr, session_id);
        
        if let Some((_, user)) = self.server.users.remove(&session_id) {
            if let Some(mut channel) = self.server.channels.get_mut(&user.channel_id) {
                channel.users.remove(&session_id);
            }
            self.server.client_handlers.remove(&session_id);
            
            let remove_msg = messages::UserRemove { session: session_id };
            self.server.broadcast_message(MessageType::UserRemove, Bytes::from(remove_msg.encode()), None).await;
            info!("Broadcasted user removal for session {}", session_id);
        }
    }
      
    async fn send_message(&self, msg_type: MessageType, payload: Bytes) -> Result<()> {
        if let Some(tx) = &self.tx {
            if tx.send((msg_type, payload.clone())).await.is_err() {
                return Err(anyhow!("Failed to send message: receiver dropped"));
            }
            
            if msg_type != MessageType::UdpTunnel && msg_type != MessageType::Ping {
                debug!("Sent {:?} ({} bytes) to session {:?}", msg_type, payload.len(), self.session_id);
            }
        }
        Ok(())
    }

    async fn handle_message(&mut self, msg_type: MessageType, payload: Bytes) -> Result<()> {
         if msg_type != MessageType::UdpTunnel && msg_type != MessageType::Ping {
            debug!("Processing {:?} from session {:?}", msg_type, self.session_id);
        }

        match msg_type {
            MessageType::Version => self.handle_version(&payload).await,
            MessageType::Authenticate => self.handle_authenticate(&payload).await,
            MessageType::Ping => self.handle_ping(&payload).await,
            MessageType::UdpTunnel => self.handle_udp_tunnel(&payload).await,
            MessageType::PermissionQuery => self.handle_permission_query(&payload).await,
            MessageType::CodecVersion => self.handle_codec_version(&payload).await,
            MessageType::TextMessage => self.handle_text_message(&payload).await,
            MessageType::UserStats => self.handle_user_stats(&payload).await,
            MessageType::UserState => self.handle_user_state_change(&payload).await,
            _ => {
                debug!("Unhandled message type: {:?}", msg_type);
                Ok(())
            }
        }
    }
      
    async fn handle_version(&self, payload: &[u8]) -> Result<()> {
        let client_version = messages::Version::decode(payload)?;
        info!("Client version: {} (0x{:08x}) OS: {} {}", 
              client_version.release, client_version.version, client_version.os, client_version.os_version);
          
        let server_version = messages::Version {
            version: self.server.version,
            release: self.server.release.clone(),
            os: "Rust".to_string(),
            os_version: "1.x".to_string(),
        };
        self.send_message(MessageType::Version, Bytes::from(server_version.encode())).await?;
        debug!("Sent server version");
        Ok(())
    }

	async fn handle_authenticate(&mut self, payload: &[u8]) -> Result<()> {
        if self.session_id.is_some() {
            warn!("Client at {} attempted to re-authenticate. Disconnecting.", self.addr);
            return Err(anyhow!("Re-authentication not allowed on active session"));
        }

        let auth = messages::Authenticate::decode(payload)?;
        info!("Authentication request: username={}, opus={}", auth.username, auth.opus);

        if let Some(server_password) = &self.server.password {
            // FIX: Use constant-time comparison instead of `auth.password != *server_password`
            if !constant_time_eq(auth.password.as_bytes(), server_password.as_bytes()) {
                warn!("Client at {} rejected: Incorrect or missing password.", self.addr);
                
                let reject_msg = messages::Reject {
                    reject_type: 4, 
                    reason: "Password required to join this server.".to_string(),
                };
                
                self.send_message(MessageType::Reject, Bytes::from(reject_msg.encode())).await?;
                
                tokio::time::sleep(Duration::from_millis(500)).await;
                
                return Err(anyhow!("Authentication failed: wrong or missing password"));
            }
        }
        let session_id = self.server.allocate_session();
        debug!("Allocated session ID: {}", session_id);
        self.session_id = Some(session_id);
        
        let user = User {
            session: session_id,
            name: if auth.username.is_empty() { format!("User{}", session_id) } else { auth.username },
            channel_id: 0,
            mute: false, 
            deaf: false, 
            suppress: false, 
            self_mute: false, 
            self_deaf: false,
            priority_speaker: false, 
            recording: false
        };
        
        info!("User authenticated: {} (session: {})", user.name, user.session);
        
        self.server.users.insert(session_id, user.clone());
        self.server.client_handlers.insert(session_id, self.tx.as_ref().unwrap().clone());
        
        if let Some(mut root) = self.server.channels.get_mut(&0) {
            root.users.insert(session_id);
        }

        self.send_crypto_setup().await?;
        self.send_channel_states().await?;
        self.send_user_states().await?;
        self.send_server_sync().await?;
        self.broadcast_user_state(user).await?;

        let last_ping_clone = self.last_ping.clone();
        let tx_clone = self.tx.as_ref().unwrap().clone();
        let shutdown_tx_clone = self.shutdown_tx.as_ref().unwrap().clone();
        let session_id_clone = self.session_id.unwrap();
        
        tokio::spawn(async move {
            ClientHandler::ping_loop(session_id_clone, last_ping_clone, tx_clone, shutdown_tx_clone).await;
        });

        Ok(())
    }

    async fn ping_loop(
        session_id: u32, 
        last_ping: Arc<tokio::sync::RwLock<SystemTime>>, 
        tx: ClientSender,
        shutdown_tx: mpsc::Sender<()>
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        'monitor: loop {
            interval.tick().await;
            
            let last = *last_ping.read().await;
            if SystemTime::now().duration_since(last).unwrap_or_default() > Duration::from_secs(30) {
                warn!("Session {} timed out - no ping received for 30+ seconds", session_id);
                break 'monitor; 
            }

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
            let ping = messages::Ping { timestamp, ..Default::default() };
            let payload = Bytes::from(ping.encode());

            if tx.send((MessageType::Ping, payload)).await.is_err() {
                debug!("Session {} write channel closed, stopping ping loop", session_id);
                break 'monitor;
            }
        }
        
        let _ = shutdown_tx.send(()).await;
    }
      
    async fn send_crypto_setup(&self) -> Result<()> {
        let crypto = messages::CryptSetup {
            key: rand::thread_rng().r#gen::<[u8; 16]>().to_vec(),
            client_nonce: rand::thread_rng().r#gen::<[u8; 16]>().to_vec(),
            server_nonce: rand::thread_rng().r#gen::<[u8; 16]>().to_vec(),
        };
        self.send_message(MessageType::CryptSetup, Bytes::from(crypto.encode())).await?;
        debug!("Sent CryptSetup to session {:?}", self.session_id);
        Ok(())
    }
      
    async fn send_channel_states(&self) -> Result<()> {
        let payloads: Vec<Bytes> = self.server.channels.iter().map(|channel| {
            let msg = messages::ChannelState {
                channel_id: channel.channel_id,
                parent: if channel.parent_id < 0 { None } else { Some(channel.parent_id as u32) },
                name: channel.name.clone(),
                links: channel.links.iter().cloned().collect(),
                description: channel.description.clone(),
                temporary: channel.temporary,
                position: channel.position,
            };
            Bytes::from(msg.encode())
        }).collect();

        for payload in payloads {
            self.send_message(MessageType::ChannelState, payload).await?;
        }
        Ok(())
    }

    async fn send_user_states(&self) -> Result<()> {
        let payloads: Vec<Bytes> = self.server.users.iter().map(|user| {
            let msg = messages::UserState {
                session: user.session,
                actor: None,
                name: user.name.clone(),
                channel_id: user.channel_id,
                mute: Some(user.mute), 
                deaf: Some(user.deaf), 
                suppress: Some(user.suppress),
                self_mute: Some(user.self_mute), 
                self_deaf: Some(user.self_deaf),
                priority_speaker: Some(user.priority_speaker), 
                recording: Some(user.recording),
                comment: "".to_string(), 
                hash: "".to_string(),
            };
            Bytes::from(msg.encode())
        }).collect();

        for payload in payloads {
            self.send_message(MessageType::UserState, payload).await?;
        }
        Ok(())
    }
      
    async fn send_server_sync(&self) -> Result<()> {
        let msg = messages::ServerSync {
            session: self.session_id.unwrap(),
            max_bandwidth: 256000,
            welcome_text: "Welcome to the Mumble Server!".to_string(),
            permissions: 0xF00FF,
        };
        self.send_message(MessageType::ServerSync, Bytes::from(msg.encode())).await?;
        info!("Sent ServerSync - Client {:?} fully synchronized", self.session_id);
        Ok(())
    }
      
    async fn broadcast_user_state(&self, user: User) -> Result<()> {
        let msg = messages::UserState {
            session: user.session,
            actor: None,
            name: user.name.clone(),
            channel_id: user.channel_id,
            mute: Some(user.mute), 
            deaf: Some(user.deaf), 
            suppress: Some(user.suppress),
            self_mute: Some(user.self_mute), 
            self_deaf: Some(user.self_deaf),
            priority_speaker: Some(user.priority_speaker), 
            recording: Some(user.recording),
            comment: "".to_string(), hash: "".to_string(),
        };
        self.server.broadcast_message(MessageType::UserState, Bytes::from(msg.encode()), self.session_id).await;
        debug!("Broadcasted UserState for {}", user.name);
        Ok(())
    }

    async fn handle_ping(&self, payload: &[u8]) -> Result<()> {
        let ping = messages::Ping::decode(payload)?;
        *self.last_ping.write().await = SystemTime::now();

        let response = messages::Ping { timestamp: ping.timestamp, ..Default::default() };
        self.send_message(MessageType::Ping, Bytes::from(response.encode())).await?;
        Ok(())
    }
      
    async fn handle_udp_tunnel(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() { return Ok(()); }
        let session_id = match self.session_id {
            Some(id) => id,
            None => return Ok(()),
        };

        let packet_type = (payload[0] >> 5) & 0x07;
        if packet_type == 1 { return Ok(()); }

        let session_varint = protobuf::encode_varint(session_id as u64);
          
        let mut broadcast_payload = Vec::with_capacity(1 + session_varint.len() + payload.len() - 1);
        broadcast_payload.push(payload[0]); 
        broadcast_payload.extend(&session_varint);
        broadcast_payload.extend_from_slice(&payload[1..]);
        let broadcast_bytes = Bytes::from(broadcast_payload);
          
        let user_channel_id = match self.server.users.get(&session_id) {
            Some(u) => u.channel_id,
            None => return Ok(()),
        };
          
        let mut recipients = HashSet::new();
        if let Some(channel) = self.server.channels.get(&user_channel_id) {
            recipients.extend(channel.users.iter());
            for link_id in &channel.links {
                if let Some(linked_channel) = self.server.channels.get(link_id) {
                    recipients.extend(linked_channel.users.iter());
                }
            }
        }

        for recipient_session in recipients {
            if recipient_session == session_id { continue; }
            if let Some(handler) = self.server.client_handlers.get(&recipient_session) {
                let _ = handler.send((MessageType::UdpTunnel, broadcast_bytes.clone())).await;
            }
        }

        Ok(())
    }

    async fn handle_permission_query(&self, payload: &[u8]) -> Result<()> {
        let query = messages::PermissionQuery::decode(payload)?;
        info!("PermissionQuery from session {:?} for channel {}", self.session_id, query.channel_id);
          
        let permissions = 0x1 | 0x2 | 0x4 | 0x8 | 0x100 | 0x200 | 0x40 | 0x400;
        let response = messages::PermissionQuery { channel_id: query.channel_id, permissions, flush: false };

        self.send_message(MessageType::PermissionQuery, Bytes::from(response.encode())).await?;
        debug!("Sent permissions 0x{:X} for channel {}", permissions, query.channel_id);
        Ok(())
    }

    async fn handle_codec_version(&self, payload: &[u8]) -> Result<()> {
        let codec = messages::CodecVersion::decode(payload)?;
        info!("Client codec: alpha={}, beta={}, prefer_alpha={}, opus={}", codec.alpha, codec.beta, codec.prefer_alpha, codec.opus);
          
        let response = messages::CodecVersion {
            alpha: -2147483637,
            beta: -2147483632,
            prefer_alpha: true,
            opus: true,
        };
        self.send_message(MessageType::CodecVersion, Bytes::from(response.encode())).await?;
        debug!("Sent codec version (Opus preferred)");
        Ok(())
    }

    async fn handle_text_message(&self, payload: &[u8]) -> Result<()> {
        let msg = messages::TextMessage::decode(payload)?;
        let session_id = self.session_id.unwrap_or(0);

        let sender_name = self.server.users.get(&session_id).map_or_else(|| format!("Session {}", session_id), |u| u.name.clone());
        info!("Text message from {} (session {}): '{}'", sender_name, session_id, msg.message);
          
        let mut recipients = HashSet::new();
        if !msg.channel_id.is_empty() {
            for channel_id in &msg.channel_id {
                if let Some(channel) = self.server.channels.get(channel_id) {
                    recipients.extend(channel.users.iter());
                }
            }
        } else if let Some(user) = self.server.users.get(&session_id) {
            if let Some(channel) = self.server.channels.get(&user.channel_id) {
                recipients.extend(channel.users.iter());
            }
        }
          
	let response = messages::TextMessage {
            actor: session_id,
            message: msg.message,
            channel_id: msg.channel_id,
            ..Default::default()
        };
        let response_bytes = Bytes::from(response.encode());
          
        for recipient_id in recipients {
            // FIX: Prevent sending the message back to the person who sent it
            if recipient_id == session_id { 
                continue; 
            }
            
            if let Some(handler) = self.server.client_handlers.get(&recipient_id) {
                let _ = handler.send((MessageType::TextMessage, response_bytes.clone())).await;
            }
        }
        Ok(())
    }      
    async fn handle_user_stats(&self, payload: &[u8]) -> Result<()> {
        let stats_req = messages::UserStats::decode(payload)?;
        info!("UserStats request for session {}", stats_req.session);
          
        let response = messages::UserStats { session: stats_req.session };
        self.send_message(MessageType::UserStats, Bytes::from(response.encode())).await?;
        debug!("Sent user stats for session {}", stats_req.session);
        Ok(())
    }

    async fn handle_user_state_change(&self, payload: &[u8]) -> Result<()> {
        let changes = messages::UserState::decode_changes(payload)?;
        info!("UserState change from session {:?}: {:?}", self.session_id, changes);
        let session_id = self.session_id.unwrap();
          
        let mut updated_user_state = None;

        let (user_name, old_channel_id) = {
            if let Some(user) = self.server.users.get(&session_id) {
                (user.name.clone(), user.channel_id)
            } else {
                return Ok(());
            }
        };

        if let Some(&new_channel_id_u64) = changes.get("channel_id") {
            let new_channel_id = new_channel_id_u64 as u32;
            if old_channel_id != new_channel_id {
                if let Some(mut old_channel) = self.server.channels.get_mut(&old_channel_id) {
                    old_channel.users.remove(&session_id);
                }
                if let Some(mut new_channel) = self.server.channels.get_mut(&new_channel_id) {
                    new_channel.users.insert(session_id);
                }
                info!("User {} moved from channel {} to {}", user_name, old_channel_id, new_channel_id);
            }
        }

        if let Some(mut user) = self.server.users.get_mut(&session_id) {
            if let Some(&val) = changes.get("channel_id") { user.channel_id = val as u32; }
            if let Some(&val) = changes.get("self_mute") { user.self_mute = val != 0; }
            if let Some(&val) = changes.get("self_deaf") { user.self_deaf = val != 0; }
            if let Some(&val) = changes.get("mute") { user.mute = val != 0; }
            if let Some(&val) = changes.get("deaf") { user.deaf = val != 0; }
            if let Some(&val) = changes.get("suppress") { user.suppress = val != 0; }
            if let Some(&val) = changes.get("priority_speaker") { user.priority_speaker = val != 0; }
            if let Some(&val) = changes.get("recording") { user.recording = val != 0; }
            
            updated_user_state = Some(user.clone());
        } 

        if let Some(updated_user) = updated_user_state {
            let state_msg = messages::UserState {
                session: session_id,
                actor: Some(session_id),
                name: updated_user.name,
                channel_id: updated_user.channel_id,
                mute: Some(updated_user.mute),
                deaf: Some(updated_user.deaf),
                suppress: Some(updated_user.suppress),
                self_mute: Some(updated_user.self_mute),
                self_deaf: Some(updated_user.self_deaf),
                priority_speaker: Some(updated_user.priority_speaker),
                recording: Some(updated_user.recording),
                ..Default::default()
            };
              
            self.server.broadcast_message(MessageType::UserState, Bytes::from(state_msg.encode()), None).await;
            debug!("Broadcasted UserState change for session {}", session_id);
        }
          
        Ok(())
    }
}

fn load_certs(filename: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = File::open(filename).map_err(|e| anyhow!("failed to open {}: {}", filename, e))?;
    let mut reader = BufReader::new(certfile);
    certs(&mut reader).collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow!("Failed to parse certificate"))
}

fn load_private_key(filename: &str) -> Result<PrivateKeyDer<'static>> {
    let keyfile = File::open(filename).map_err(|e| anyhow!("failed to open {}: {}", filename, e))?;
    let mut reader = BufReader::new(keyfile);
    private_key(&mut reader)
        .and_then(|key| key.ok_or(std::io::Error::new(std::io::ErrorKind::NotFound, "no private key found")))
        .map_err(|_| anyhow!("Failed to parse private key"))
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
      
    let args: Vec<String> = std::env::args().collect();
    let mut password = None;
    
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--password" && i + 1 < args.len() {
            password = Some(args[i + 1].clone());
            i += 1;
        }
        i += 1;
    }

    let host = "0.0.0.0";
    let port = 31839;
    let addr = format!("{}:{}", host, port);
    let certfile = "server.crt";
    let keyfile = "server.key";

    let server = Arc::new(MumbleServer::new(password));
    server.init_root_channel().await;
    server.create_channel("General", 0).await;
    server.create_channel("Gaming", 0).await;
    server.create_channel("Music", 0).await;
      
    let separator = "=".repeat(60);
    info!("{}", separator);
    info!("Mumble Server Starting");
    info!("{}", separator);
    info!("Version: {}", server.release);
    info!("Host: {}", host);
    info!("Port: {}", port);
    info!("Certificate: {}", certfile);
    info!("Key: {}", keyfile);
    info!("Channels: {}", server.channels.len());
    info!("{}", separator);

    if let Err(e) = server.clone().start(&addr, certfile, keyfile).await {
        error!("Server error: {}", e);
    }

    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0;
    for i in 0..a.len() {
        // XOR (^) evaluates to 0 if the bytes are identical.
        // OR (|) accumulates any differences without branching.
        result |= a[i] ^ b[i];
    }

    // black_box prevents the compiler from outsmarting us and 
    // replacing this loop with a short-circuiting `memcmp`.
    black_box(result) == 0
}
