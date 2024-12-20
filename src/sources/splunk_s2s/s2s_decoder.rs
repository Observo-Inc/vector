use bytes::{Buf, BytesMut};
use codecs::StreamDecodingError;
use indexmap::IndexMap;
use regex::Regex;
use snafu::Snafu;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::{fmt, io};
use tokio_util::codec::Decoder;
use vector_core::event::{LogEvent, Value};

pub(crate) struct S2SDecoder {
    s2s_decoder_state: S2SDecoderState,
    handshake_complete: bool,
    fwd_header: Option<FwdHeader>,
    fwd_capabilities: Option<HashMap<String, String>>,
    fwd_info: Option<FwdInfo>,
    _allowed: bool,
    _fwd_token: String,
    _tokens: HashSet<String>,
    parsed_frames: Vec<(S2SEventFrame, usize)>,
    _ack: bool,
}

impl Decoder for S2SDecoder {
    type Item = (S2SEventFrame, usize);
    type Error = S2SDecoderError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.parsed_frames.is_empty() {
            match self.handle_connection(buf) {
                Ok(frames) => {
                    self.parsed_frames = frames;
                }
                Err(err) => {
                    debug!("[Warning] Ignoring decode error: {:?}", err);
                    return Ok(None)
                }
            }
        }
        match self.parsed_frames.pop() {
            None => {
                Ok(None)
            }
            Some(frame) => {
                trace!("Handling frame {:?}", frame);
                Ok(Some(frame))
            }
        }
    }
}

impl S2SDecoder {
    pub(crate) fn new() -> Self {
        S2SDecoder {
            s2s_decoder_state: S2SDecoderState::new(),
            handshake_complete: false,
            fwd_header: None,
            fwd_capabilities: None,
            fwd_info: None,
            _allowed: false,
            _fwd_token: String::from(""),
            _tokens: HashSet::new(),
            parsed_frames: vec![],
            _ack: false,
        }
    }

    fn handle_connection(&mut self, buf: &mut BytesMut) -> Result<Vec<(S2SEventFrame, usize)>, S2SDecoderError> {
        if !self.handshake_complete {
            if self.fwd_header.is_none() {
                let ret = self.handshake(buf);
                debug!("Handshake returned: {:?}", ret);
                return ret;
            }

            if self.fwd_header.is_some() && self.fwd_capabilities.is_none() {
                return match self.read_fwd_capabilities(buf) {
                    Ok(frames) => {
                        debug!("Capabilities returned: {:?}", frames);
                        Ok(vec![frames])
                    }
                    Err(err) => {
                        debug!("[Warning] Error ignored: {:?}", err);
                        Err(S2SDecoderError::InSufficientData)
                    }
                }
            }
            match self.read_fwd_info(buf) {
                Ok(frames) => {
                    debug!("Fwd Info returned: {:?}", frames);
                    Ok(vec![frames])
                }
                Err(err) => {
                    debug!("[Warning] Error ignored: {:?}", err);
                    Err(S2SDecoderError::InSufficientData)
                }
            }
        } else {
            self.do_process(buf)
        }
    }

    fn read_fwd_capabilities(&mut self, buf: &mut BytesMut) -> Result<(S2SEventFrame, usize), S2SDecoderError> {
        let option = self.s2s_decoder_state.read_fwd_capabilities(buf);
        if option.is_some() {
            let (s2s_fwd_capabilities_event, size) = option.unwrap();
            self.fwd_capabilities = s2s_fwd_capabilities_event.capabilities_map.clone();
            return Ok((s2s_fwd_capabilities_event, size))

        }
        Err(S2SDecoderError::GenericError { message: String::from("S2S_FWD_CAPABILITIES error") })
    }

    fn read_fwd_info(&mut self, buf: &mut BytesMut) -> Result<(S2SEventFrame,usize), S2SDecoderError> {
        let result = self.s2s_decoder_state.read_fwd_info(buf);
        match result {
            Ok(option) => {
                match option {
                    None => {
                        Err(S2SDecoderError::GenericError { message: String::from("S2S_FWD_INFO error") })
                    },
                    Some((s2s_event, size)) => {
                        let s2s_event = s2s_event;
                        self.fwd_info = s2s_event.fwd_info.clone();
                        self.handshake_complete = true;
                        Ok((s2s_event, size))
                    }
                }
            }
            Err(_e) => {
                Err(S2SDecoderError::GenericError { message: String::from("S2S_FWD_INFO error") })
            }
        }
    }

    fn handshake(&mut self, buf: &mut BytesMut) -> Result<Vec<(S2SEventFrame, usize)>, S2SDecoderError> {
        let mut s2s_header_event = S2SEventFrame::default();
        let fwd_header = self.s2s_decoder_state.read_fwd_header(buf);
        let response = self.s2s_decoder_state.get_s2s_signature();
        s2s_header_event.header_buffer = Some(response);
        match fwd_header.clone() {
            None => {
                Err(S2SDecoderError::InSufficientData)
            }
            Some((fwd_header, offset)) => {
                self.fwd_header = Some(fwd_header.clone());
                s2s_header_event.fwd_header = Some(fwd_header);
                Ok(vec![(s2s_header_event, offset)])
            }
        }
    }

    fn do_process(&mut self, buf: &mut BytesMut) -> Result<Vec<(S2SEventFrame, usize)>, S2SDecoderError> {
        let mut offset = Offset::new(0);
        offset.end = buf.len() as i32;
        debug!("processing event. Offset: {}, buffer: {}", offset.offset, buf.len());
        if buf.is_empty() {
            return Err(S2SDecoderError::InSufficientData);
        }
        let command_code = buf[offset.offset as usize];
        let read_command = Command::from_u8(command_code);
        match read_command {
            Some(command) => {
                match command {
                    Command::RegisterChannel => {
                        let event_option = self.s2s_decoder_state.register_channel(buf, &mut offset);
                        if event_option.is_some() {
                            return Ok(vec![(event_option.unwrap(), 0)]);
                        }
                    }
                    Command::ReadEvent => {

                        match self.s2s_decoder_state.process_event(buf, &mut offset) {
                            Ok(events) => {
                                return Ok(events);
                            }
                            Err(S2SDecoderError::InSufficientData) => {
                                debug!("insufficent data. reading more packets");
                                return Err(S2SDecoderError::InSufficientData)
                            }
                            Err(_) => {
                                debug!("Failed to read event");
                            }
                        }
                    }
                    Command::AbandonChannel => {
                        match self.s2s_decoder_state.abandon_channel(buf, &mut offset) {
                            Ok(event) => {
                                debug!("Successfully abandon event: {}", event);
                            }
                            Err(_) => {
                                debug!("Failed to abandon event");
                            }
                        }
                    }
                    Command::Timezone => {
                        self.s2s_decoder_state.read_time_zone(buf, &mut offset);
                    }
                    _ => {
                        debug!("Command {:?}  0x{:02X} offset: {}\n", command, command_code, offset.offset);

                        if Command::is_command(command_code) {
                            offset.advance(1);
                        }
                    }
                }
            }
            None => {
                debug!("Unknown command: 0x{:02X} offset: {}\n", command_code, offset.offset);
                offset.advance(1);
            }
        }

        // self.find_next_command(&mut offset, buf);

        buf.advance(offset.offset as usize);
        Err(S2SDecoderError::InSufficientData)
    }

    fn _find_next_command(&mut self, offset: &mut Offset, buf: &mut BytesMut) {
        while offset.offset < buf.len() as i32 {
            let command_code = buf[offset.offset as usize];
            let is_command = Command::is_command(command_code);
            if is_command {
                return;
            }
            offset.advance(1);
        }
    }
}


struct S2SDecoderState {
    _handshake_complete: bool,
    channel: HashMap<i32, Channel>,
    _fwd_header: Option<FwdHeader>,
    _fwd_capabilities: Option<HashMap<String, String>>,
    fwd_info: Option<FwdInfo>,
    ack: bool,
    allowed: bool,
    fwd_token: String,
    tokens: HashSet<String>,
    pending_to_ack: Vec<i32>,
    prev_line: HashMap<i32, String>,
}

impl S2SDecoderState {
    fn new() -> Self {
        S2SDecoderState {
            _handshake_complete: false,
            channel: HashMap::new(),
            _fwd_header: None,
            _fwd_capabilities: None,
            ack: false,
            allowed: false,
            tokens: HashSet::new(),
            fwd_token: String::new(),
            fwd_info: None,
            pending_to_ack: Vec::new(),
            prev_line: HashMap::new(),
        }
    }

    fn is_payload_header(&self, payload_value: i32) -> bool {
        (payload_value & EventFlags::SOURCE_METADATA) > 0
    }

    fn is_payload_packet_id(&self, payload_value: i32) -> bool {
        (payload_value & EventFlags::EVENT_ID) > 0
    }

    fn is_payload_timestamp(&self, payload_value: i32) -> bool {
        (payload_value & EventFlags::TIME) > 0
    }

    fn is_payload_broken(&self, payload_value: i32) -> bool {
        (payload_value & EventFlags::BROKEN) > 0
    }

    fn _is_payload_contains_extra_metadata(&self, payload_value: i32) -> bool {
        (payload_value & 65536) > 0
    }

    fn parse_event(&mut self, buffer: &mut BytesMut, offset: &mut Offset) -> Result<S2SEventFrame, S2SDecoderError> {
        let mut event = S2SEventFrame::default();
        let drop_control_fields = false;

        // VERIFY READ EVENT
        let command_code = self.read_u8(buffer, offset.advance(1) as usize);
        if command_code != Command::ReadEvent as u8 {
            return Err(S2SDecoderError::UnexpectedOpCode { opcode: command_code });
        }

        event.command = Some(Command::ReadEvent);

        // GET CHANNEL ID
        let channel_id = self.read_leb128_i32(buffer, offset);

        // CHECK IF CHANNEL EXISTS
        if !self.channel.contains_key(&channel_id) {
            return Err(S2SDecoderError::UnknownChannel { channel_id: channel_id as u64 });
        }

        // READING CHANNEL DATA AND SETTING TO EVENT
        // let channel = self.channel.get_mut(&channel_id).unwrap();
        let channel = self.channel.get(&channel_id).unwrap();
        event.channel = Some(channel_id);
        event.source = channel.metadata.get("source").cloned().unwrap_or("default_source".to_string());
        event.host = channel.metadata.get("host").cloned().unwrap_or("default_host".to_string());
        event.sourcetype = channel.metadata.get("sourcetype").cloned().unwrap_or("default_sourcetype".to_string());
        let channel_headers = channel.headers.clone();


        // READ PAYLOAD CODE
        let payload_code = self.read_leb128_i32(buffer, offset);
        if PayloadType::is(payload_code) {
            let payload = PayloadType::of(payload_code);
            event.payload_type = payload.clone();
            // debug!("READ_EVENT payload is {:?}", payload)
        }

        // Flags as binary of payload_code
        event.flags = format!("{:b}", payload_code);

        // BROKEN EVENT COUNT
        if self.is_payload_header(payload_code) {
            self.read_leb128_i32(buffer, offset);
            self.read_leb128_i32(buffer, offset);
            event.broken_event_count = self.read_leb128_i32(buffer, offset);
        }

        // SET S2S id
        if self.is_payload_packet_id(payload_code) {
            let event_id = self.read_leb128_i32(buffer, offset);
            debug!("[read_event] event id: {}", event_id);
            event.__s2s_id = Some(event_id);
        }

        // SET Timestamp
        if self.is_payload_timestamp(payload_code) {
            let timestamp = self.read_leb128_i64(buffer, offset);
            event.time = timestamp;
        }

        let mut broken_fields: Vec<String> = Vec::new();

        // SET IS_BROKEN payload
        if self.is_payload_broken(payload_code) {
            event.is_broken = true;
        }

        event.num_fields = self.read_leb128_i32(buffer, offset);
        let mut _value_i32: i32 = -1;

        let mut array: Vec<ObjectData> = Vec::new();
        let mut key_type_array: Vec<KeyTypeData> = Vec::new();

        for _ in 0..event.num_fields {
            let mut a = self.read_leb128_i32(buffer, offset) as i64; // because we want to and with 4294967231
            a = a & 4294967231;
            let key_mark = a & 3; //
            let value_mark = a.wrapping_shr(2) & 15;
            let mut field_action = FieldAction::KeepTop;
            let mut key = String::from("");
            let mut value = String::from("");

            let mut is_value_string = true;
            match key_mark {
                0 => {
                    let size = self.read_leb128_i32(buffer, offset);
                    let start = offset.offset;
                    offset.advance(size);
                    let mut t: u32 = 0;
                    if size > 4 {
                        match self.read_uint32_be(buffer, start) {
                            Ok(value) => {
                                t = value;
                            }
                            Err(_) => {
                                return Err(S2SDecoderError::GenericError { message: String::from("failed in read_uint32_be") });
                            }
                        }
                    }
                    let s = match self.read_uint32_be(buffer, start + size - 4) {
                        Ok(value) => {
                            value
                        }
                        Err(_err) => {
                            return Err(S2SDecoderError::GenericError { message: String::from("failed in read_uint32_be") });
                        }
                    };

                    let q = s ^ t;
                    match q {
                        84543253 => {
                            key = String::from("host");
                        }
                        824770572 => {
                            key = String::from("index");
                        }
                        941037316 => {
                            key = String::from("source");
                        }
                        958137348 => {
                            key = String::from("sourcetype");
                        }
                        _ => {
                            if drop_control_fields {
                                field_action = FieldAction::DROP;
                            } else {
                                field_action = FieldAction::KeepCtrl;
                                match key_mark {
                                    756026645
                                    | 1007419656
                                    | 253104919
                                    | 739246348
                                    | 1600680046
                                    | 1601070692
                                    | 789648668
                                    | 723393801 => {
                                        field_action = FieldAction::DROP;
                                    }
                                    805833227 => {
                                        key = String::from("_cooked");
                                    }
                                    940710925 => {
                                        key = String::from("_guid");
                                    }
                                    906431235 => {
                                        key = String::from("_ingLatChained");
                                    }
                                    805634325 => {
                                        key = String::from("_ingLatColor");
                                    }
                                    387715586 => {
                                        key = String::from("_savedHost");
                                    }
                                    253498114 => {
                                        key = String::from("_savedPort");
                                    }
                                    806555431 => {
                                        key = String::from("crcSalt");
                                    }
                                    454563081 => {
                                        key = String::from("interval");
                                    }
                                    _ => {
                                        let end = (start + size) as usize;
                                        key = String::from_utf8_lossy(&buffer[start as usize..end]).to_string();
                                    }
                                }
                            }

                            // debug!("READ_EVENT :: INNER SWITCH KEY key_mark: {}, inner_mark: {}",key_mark,q);
                        }
                    }
                }
                1 => {
                    let l = self.read_leb128_i32(buffer, offset);

                    if l >= 0 && (l as usize) < channel_headers.len() {
                        key = channel_headers[l as usize].clone();
                    }
                }
                2 => {
                    let l = self.read_leb128_i32(buffer, offset) as usize;
                    debug!("READ_EVENT :: PREDEFINED_KV_STRINGS[l]: {}", l);
                    key = get_key_from_predefined_strings(l);
                    debug!("READ_EVENT :: PREDEFINED_KV_STRINGS[l]: {}", key);
                }
                3 => {
                    let size = self.read_leb128_i32(buffer, offset);
                    let start = offset.offset as usize;
                    let end = start + size as usize;
                    key = String::from_utf8_lossy(&buffer[start..end]).to_string();
                    offset.advance(size);
                }
                _ => {
                    debug!("READ_EVENT :: UNEXPECTED_KEY_TYPE {}", key_mark);
                }
            }
            match value_mark {
                0 | 10 => {
                    // read number
                    _value_i32 = self.read_leb128_i32(buffer, offset);
                    is_value_string = false;
                    debug!("READ_EVENT VALUE_MARK_SWITCH KEY value_mark: {},  value_i32: {}", value_mark, _value_i32);
                }
                1 => {
                    let size = self.read_leb128_i32(buffer, offset);
                    if field_action.value() & THREE > 0 {
                        let start = offset.offset as usize;
                        let end = start + size as usize;
                        value = String::from_utf8_lossy(&buffer[start..end]).to_string();
                    }
                    offset.advance(size);
                }
                2 => {
                    let index = self.read_leb128_i32(buffer, offset) as usize;
                    value = get_key_from_predefined_strings(index)
                }
                3 | 4 | 5 | 6 | 7 | 8 | 9 => {
                    let data = ObjectData {
                        key: key.clone(),
                        _raw_offset: self.read_leb128_i32(buffer, offset),
                        _length: self.read_leb128_i32(buffer, offset),
                        _flag: field_action.clone(),
                    };
                    array.push(data);
                }
                12 => {
                    let t = ((a as u32) >> 6) == 0;
                    let index = self.read_leb128_i32(buffer, offset);
                    if t {
                        let data = KeyTypeData {
                            key: key.clone(),
                            _index: index,
                            num_type: String::from("int"),
                            flag: field_action.clone(),
                            precision: -1,
                            _scale: -1,
                        };
                        key_type_array.push(data);
                    } else {
                        let data = KeyTypeData {
                            key: key.clone(),
                            _index: index,
                            num_type: String::from("float"),
                            flag: field_action.clone(),
                            precision: self.read_leb128_i32(buffer, offset),
                            _scale: self.read_leb128_i32(buffer, offset),
                        };
                        key_type_array.push(data);
                    }
                    _value_i32 = -1;
                    is_value_string = false;
                }
                _ => {
                    // return Err(ParseError::GenericError(String::from("unexpected")));
                    debug!("READ_EVENT :: UNEXPECTED_VALUE_TYPE")
                }
            }

            if field_action.value() & THREE > 0 {
                if (is_value_string && !value.is_empty()) || !is_value_string {
                    if field_action.value() & FieldAction::KeepTop.value() > 0 {
                        if !event.fields.contains_key(&key) {
                            event.fields.insert(key.clone(), Vec::new());
                        }
                        event.fields.get_mut(&key).unwrap().push(value.clone());

                        if !event.is_broken && key_mark == 3 {
                            broken_fields.push(value.clone());
                        }
                    } else {
                        event.control_fields.insert(key.clone(), value.clone());
                        // event.control_fields.push(key.clone());
                        // event.control_fields.push(value.clone());

                    }
                }
            }

            // debug!("READ_EVENT key_mark is {}, value_mark is {}, key is {}, value is {}", key_mark, value_mark, key, value);
        }

        // parse numeric metadata in kafka s2s
        if payload_code & EventFlags::DOUBLES > 0 {
            debug!("READ_EVENT:: EVENT_FLAG DOUBLES");
            let t = self.read_leb128_i32(buffer, offset);
            let s = offset.offset + t;
            for item in key_type_array.iter_mut() {
                let _mark = offset.advance(8);
                let mut n = buffer.get_f64_le();
                debug!("READ_EVENT:: DOUBLE LEB128: {}, precision: {}", n, item.precision);
                if item.flag.value().clone() & FieldAction::DROP.value() > 0 {
                    continue;
                }
                if item.num_type.eq("float") {
                    n = to_precision(n, item.precision as usize);
                }
                if item.flag.value().clone() & FieldAction::KeepTop.value() > 0 {} else {
                    event.control_fields.insert(item.key.clone(), format!("{}", n));
                }
            }
            offset.advance(s - offset.offset);
        }

        if payload_code & EventFlags::RAW > 0 {
            let size = self.read_leb128_i32(buffer, offset);
            event.data_size = size.clone();
            let start = offset.offset as usize;
            let mut end = start + size as usize;

            if end > buffer.len() {
                event.done = false;
                end = buffer.len();
                let str = String::from_utf8_lossy(&buffer[start..end]).to_string();
                event.raw = str.clone();
                return Err(S2SDecoderError::InSufficientData);
                // offset.advance(end - start);
                // event is larger than the buffer
            } else {
                event.done = true;
                let str = String::from_utf8_lossy(&buffer[start..end]).to_string();
                event.raw = str.clone();
                offset.advance(size);
            }

            for item in array.iter_mut() {
                debug!("READ_EVENT:: RAW: item: {}", item.key);
            }
        }

        if !event.is_broken && broken_fields.len() > 0 {
            event.breaker_fields = broken_fields;
        }

        if payload_code & EventFlags::LAST_EVENT > 0 {
            event.fin = true
        }

        buffer.advance(offset.offset as usize);
        Ok(event)
    }

    // async fn read_double_le(&mut self, buffer: &mut BytesMut, _offset: usize) -> f64 {
    //     let mut cursor = Cursor::new(buffer);  // Create a cursor from the slice
    //     let value = cursor.read_f64();  // Read as f64 in little-endian
    //     value.unwrap_or_default()
    // }


    fn process_event(&mut self, buffer: &mut BytesMut, offset: &mut Offset) -> Result<Vec<(S2SEventFrame, usize)>, S2SDecoderError> {
        let result = self.parse_event(buffer, offset);
        let mut s2s_event: S2SEventFrame = match result {
            Ok(s2s_event) => {
                s2s_event
            }
            Err(e) => {
                debug!("error while reading event {:?}", e);
                return Err(e);
            }
        };

        if !s2s_event.done {
            // we are skipping the event in java... ???
        }

        if s2s_event.payload_type == PayloadType::LogData64KReplayPacket {
            // process 64k replay packet
            // handle separately
        }

        if s2s_event.data_size == 0 {
            // log empty packet
            // if ack enabled, send ack else skip
            // skip further processing
        }


        if let Some(fwd_info) = self.fwd_info.as_ref() {
            if let Some(fwd_type) = fwd_info._forwarder_info.get("fwdType") {
                s2s_event.fwd_type = fwd_type.clone();
            }
        }

        if !self.fwd_token.is_empty() {
            s2s_event.s2s_token = self.fwd_token.clone();
        }

        if s2s_event.is_broken {
            s2s_event.channel = None;
        } else if s2s_event.is_broken {
            // set timezone
        }

        if self.ack & (s2s_event.__s2s_id.is_some()) {
            // push ack
            debug!("[read_event] should ack id: {:?}", s2s_event.__s2s_id);
            self.pending_to_ack.push(s2s_event.__s2s_id.unwrap());
        }

        s2s_event.version = Some(String::from("v4"));


        let s2s_events_option =  self.post_process_event(&mut s2s_event);
        if s2s_events_option.is_some() {
            return Ok(s2s_events_option.unwrap());
        }
        Err(S2SDecoderError::InSufficientData)

    }

    fn post_process_event(&mut self, s2s_event: &mut S2SEventFrame) -> Option<Vec<(S2SEventFrame, usize)>> {
        let event_data_length = s2s_event.data_size.clone() as usize;
        let mut complete_data = s2s_event.raw.clone();


        if s2s_event.channel.is_none() {
            debug!("[read_event] no channel data. event: {}", s2s_event);
            return None;
        }
        let channel_id = s2s_event.channel.unwrap();

        let prev_line_present = self.prev_line.contains_key(&channel_id);
        if prev_line_present {
            let prev_line_str = self.prev_line.get(&channel_id).unwrap().clone();
            complete_data = format!("{}{}", complete_data, prev_line_str);
            self.prev_line.remove(&channel_id);
        }
        s2s_event.raw = complete_data.clone();
        let mut is_64k_packet = false;
        if s2s_event.channel.is_some() {
            let data = s2s_event.raw.clone();
            let lines: Vec<&str> = data.lines().collect();
            let _s2s_id = s2s_event.__s2s_id.unwrap();
            if event_data_length >= 65535 || event_data_length % 8192 == 0 {
                is_64k_packet = true;
            }
            let s2s_events: Vec<(S2SEventFrame, usize)> = self.parse_lines(s2s_event, lines, is_64k_packet);
            return Some(s2s_events);
        }
        None
    }

    fn parse_lines(&mut self, s2sevent: &mut S2SEventFrame, lines: Vec<&str>, _is_64k_packet: bool) -> Vec<(S2SEventFrame, usize)> {
        // here i'm doing based on only new line chars
        // however, this is a config at source type level in java implementation
        if lines.is_empty() {
            return vec![(s2sevent.clone(), 0)];
        }
        let mut s2s_events: Vec<(S2SEventFrame, usize)> = Vec::new();
        for line in lines {
            let mut cloned_s2s_event = s2sevent.clone();
            cloned_s2s_event.raw = line.to_string();
            s2s_events.push((cloned_s2s_event, line.len()));
        }
        s2s_events
    }

    fn read_leb128_i32(&mut self, buffer: &mut BytesMut, offset: &mut Offset) -> i32 {
        let mut result = 0;
        let mut shift = 0;
        loop {
            if offset.offset >= buffer.len() as i32 {
                return result;
            }

            let mark = offset.advance(1) as usize;
            let byte = buffer[mark] as i32;
            let low_bits = byte & 0x7F;
            let high_bits = byte & 0x80;
            let low_bits_32 = low_bits;
            let shifted_value = low_bits_32.wrapping_shl(shift as u32);
            result = result | shifted_value;
            if high_bits == 0 {
                break;
            }
            shift += 7;
        }
        result
    }

    fn read_leb128_i64(&mut self, buffer: &mut BytesMut, offset: &mut Offset) -> i64 {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        loop {
            if offset.offset >= buffer.len() as i32 {
                return result;
            }
            let mark = offset.advance(1) as usize;
            let byte = buffer[mark] as i64;
            let low_bits = byte & 0x7F;
            let high_bits = byte & 0x80;
            let low_bits_32 = low_bits;
            let shifted_value = low_bits_32.wrapping_shl(shift);
            result = result | shifted_value;
            if high_bits == 0 {
                break;
            }
            shift += 7;
        }
        result
    }

    fn register_channel(&mut self, buffer: &mut BytesMut, offset: &mut Offset) -> Option<S2SEventFrame> {
        if self.channel.len() == 300 {
            debug!("max channels reached");
            return None;
        }
        let channel: Channel = self.read_channel_registration(buffer, offset);
        if channel.channel_id < 1 {
            debug!("failed to register channel. {}", channel.channel_id);
            return None;
        }

        if self.channel.contains_key(&channel.channel_id) {
            debug!("already registered: {}", channel.channel_id);
            return None;
        }


        for (key, value) in &channel.metadata {
            debug!("registering channel id: {}, {}: {}", channel.channel_id, key, value);
        }
        debug!("registered channel: {}", channel);
        let mut event = S2SEventFrame::default();
        event.channel = Some(channel.channel_id);
        event.source = channel.metadata.get("source").cloned().unwrap_or("default_source".to_string());
        event.host = channel.metadata.get("host").cloned().unwrap_or("default_host".to_string());
        event.sourcetype = channel.metadata.get("sourcetype").cloned().unwrap_or("default_sourcetype".to_string());

        self.channel.insert(channel.channel_id, channel);
        buffer.advance(offset.offset as usize);
        return Some(event);
    }

    fn read_channel_registration(&mut self, buffer: &mut BytesMut, offset: &mut Offset) -> Channel {
        let r = self.read_u8(buffer, offset.advance(1) as usize);
        if r != Command::RegisterChannel as u8 {
            debug!("Invalid RegisterChannel");
            return Channel {
                channel_id: -1,
                value_1: String::from(""),
                key_1: String::from(""),
                extra: String::from(""),
                headers: Vec::new(),
                metadata: HashMap::new(),
            };
        }
        let s = self.read_leb128_i32(buffer, offset);
        self.build_channel_data(buffer, offset, s)
    }

    fn read_time_zone(&mut self, buffer: &mut BytesMut, offset: &mut Offset) {
        offset.advance(1);
        let size = self.read_leb128_i32(buffer, offset);
        offset.advance(size);
    }

    fn abandon_channel(&mut self, buffer: &mut BytesMut, offset: &mut Offset) -> Result<S2SEventFrame, S2SDecoderError> {
        offset.advance(1);
        let channel_id = self.read_leb128_i32(buffer, offset);
        let mut event = S2SEventFrame::default();
        if !self.channel.contains_key(&channel_id) {
            debug!("[abandon_channel] channel not found for deregistering. channel_id {}", channel_id);
            return Err(S2SDecoderError::UnknownChannel { channel_id: channel_id as u64 }); // check
        }
        self.channel.remove(&channel_id);
        debug!("[abandon_channel] channel removed {}", channel_id);
        event.command = Some(Command::AbandonChannel);
        event.fin = true;
        event.channel = Some(channel_id);
        buffer.advance(offset.offset as usize);
        Ok(event)
    }

    fn build_channel_data(&mut self, buffer: &mut BytesMut, offset: &mut Offset, channel_id: i32) -> Channel {
        let _channel = channel_id.clone();
        let mut ch: Channel = Channel {
            channel_id,
            value_1: String::from(""),
            key_1: String::from(""),
            extra: String::from(""),
            headers: Vec::new(),
            metadata: HashMap::new(),
        };
        for _i in 0..4 {
            let r = self.read_leb128_i32(buffer, offset);
            if r == 0 {
                continue;
            }
            let a = offset.offset as usize;
            let mut b = (offset.offset + r - 1) as usize;
            if b >= buffer.len() {
                debug!("REGISTER_CHANNEL maxing :: a {}, b {}", a, b);
                b = buffer.len();
            }
            let s = String::from_utf8_lossy(&buffer[a..b]).to_string();
            let s_clone = s.clone();
            offset.advance(r - 1);
            let pattern = String::from("::");
            let n = self.split(s, &pattern, 1);
            if n.len() == 2 {
                ch.metadata.insert(n[0].clone(), n[1].clone());
            } else {
                ch.extra = s_clone.clone();
            }
        }

        let n = self.read_leb128_i32(buffer, offset);
        debug!("register_channel: n: {}", n);

        if n > 0 {
            for _r in 0..n {
                let x = self.read_leb128_i32(buffer, offset);
                let start = offset.offset as usize;
                let end = start + x as usize;
                let y = String::from_utf8_lossy(&buffer[start..end]).to_string().clone();
                debug!("[build_channel_data] header is {}", y);
                offset.advance(x);
                ch.headers.push(y);
            }
        }
        ch
    }

    fn split(&mut self, mut str: String, pattern: &String, r: usize) -> Vec<String> {
        let mut s: Vec<String> = Vec::new();
        let limit = r;
        let re = Regex::new(pattern).expect("Invalid regexp");

        for _ in 0..limit {
            if let Some(captures) = re.find(&str) {
                let part = str[..captures.start()].to_string();
                s.push(part);
                str = str[captures.end()..].to_string();
            } else {
                break;
            }
        }
        s.push(str.to_string());
        s
    }

    fn read_str(&mut self, buf: &mut BytesMut, offset: i32, val: i32) -> String {
        let mut i: usize = (offset + val) as usize;
        while i > offset as usize && buf[i - 1] == 0 {
            i = i - 1
        }

        let line = String::from_utf8_lossy(&buf[offset as usize..i]).to_string();
        line
    }

    fn read_fwd_header(&mut self, buf: &mut BytesMut) -> Option<(FwdHeader, usize)> {
        if buf.len() < FWD_HEADER_MIN_LENGTH {
            return None;
        }
        let mut offset = Offset::new(0);

        // read signature
        let mut start = offset.offset;
        offset.advance(128);
        let signature = self.read_str(buf, start, 128);
        let splunk_signature = String::from("--splunk-cooked-mode-v3--");
        if signature != splunk_signature {
            return None;
        }

        debug!("Splunk signature: {}", signature);

        // read server name
        start = offset.offset;
        let server_name = self.read_str(buf, start, 256);
        offset.advance(256);
        if server_name.is_empty() {
            return None;
        }

        // read port
        start = offset.offset;
        let port_str = self.read_str(buf, start, 16);
        offset.advance(16);
        if port_str.is_empty() {
            return None;
        }

        let mut port_i32 = -1;

        match port_str.parse::<i32>() {
            Ok(port) => {
                port_i32 = port;
            }
            Err(e) => error!("Failed to parse number: {}", e),
        }

        let fwd_header = FwdHeader {
            _signature: signature,
            _server_name: server_name,
            _port: port_i32,
        };

        buf.advance(offset.offset as usize);
        Some((fwd_header, offset.offset as usize))
    }

    fn read_fwd_capabilities(&mut self, buffer: &mut BytesMut) -> Option<(S2SEventFrame, usize)> {
        let mut offset = Offset::new_(0, true);
        offset.end = buffer.len() as i32;
        let s2s_option = self.read_legacy_event(buffer, &mut offset);
        if s2s_option.is_none() {
            return None;
        }
        let mut legacy_s2s_event = s2s_option.unwrap();
        let capabilities_option = legacy_s2s_event.control_fields.get_mut("__s2s_capabilities");
        if capabilities_option.is_none() {
            debug!("Failed to read. Should throw error. FWD capabilities not set.");
            return None;
        }
        let capabilities = capabilities_option.unwrap().as_str().clone();
        let capabilities_map = self.parse_raw_string(capabilities, ";");

        offset.offset;
        legacy_s2s_event.capabilities_map = Some(capabilities_map);

        buffer.advance(offset.offset as usize);
        Some((legacy_s2s_event, offset.offset as usize))
    }

    fn parse_raw_string(&mut self, str: &str, pat: &str) -> HashMap<String, String> {
        let mut map: HashMap<String, String> = HashMap::new();
        // / Split the string by semicolons to get key-value pairs
        for pair in str.split(pat) {
            // Split each pair by '=' to get key and value
            let mut parts = pair.split('=');

            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                map.insert(key.to_string(), value.to_string());
            }
        }
        map
    }

    fn read_fwd_info(&mut self, buffer: &mut BytesMut) -> Result<Option<(S2SEventFrame, usize)>, S2SDecoderError> {
        // debug!("FWD info checking");
        let mut offset = Offset::new_(0, true);
        offset.end = buffer.len() as i32;

        let s2s_event_option = self.read_legacy_event(buffer, &mut offset);
        if s2s_event_option.is_none() {
            return Err(S2SDecoderError::GenericError { message: String::from("no legacy event") });
        }

        let mut s2s_event = s2s_event_option.unwrap();
        if s2s_event.sourcetype != "fwdinfo" {
            return Err(S2SDecoderError::GenericError { message: String::from("Invalid fwdinfo") });
        }
        let mut token = String::from("");
        let token_option = s2s_event.control_fields.get_mut("__s2s_token");
        if !self.allowed && !self.tokens.is_empty() {
            if token_option.is_some() {
                token = token_option.unwrap().to_string();
                if !self.tokens.contains(&token) {
                    return Err(S2SDecoderError::GenericError { message: String::from("Invalid token") });
                }
            }
        }

        let capabilities_option = s2s_event.control_fields.get_mut("__s2s_capabilities");
        if capabilities_option.is_none() {
            debug!("Failed to read. Should throw error. FWD capabilities not set.");
            return Err(S2SDecoderError::GenericError { message: String::from("Invalid capabilities") });
        }
        let capabilities = capabilities_option.unwrap().as_str().clone();
        let capabilities_map = self.parse_raw_string(capabilities, ";");
        let raw = s2s_event.raw.clone();
        let mut forwarder_info = self.get_forwarder_info(&raw);


        forwarder_info.insert(String::from("__s2s_token"), token.clone());
        forwarder_info.insert(String::from("capabilities"), capabilities.to_string());

        // buffer.drain(0..offset.offset as usize);

        debug!("S2S event legacy: {:?}", s2s_event);

        let fwd_info = FwdInfo {
            _capabilities: capabilities_map,
            _s2s_token: token.clone(),
            _forwarder_info: forwarder_info,
        };

        s2s_event.fwd_info = Some(fwd_info);
        buffer.advance(offset.offset as usize);
        Ok(Some((s2s_event, offset.offset as usize)))
    }

    fn get_forwarder_info(&mut self, str: &str) -> HashMap<String, String> {
        let fwd_info_prefix_len = String::from("ForwarderInfo ").len();
        let sub_str = &str[fwd_info_prefix_len..];
        self.parse_raw_string(sub_str, " ")
    }

    fn read_legacy_event(&mut self, buffer: &mut BytesMut, offset: &mut Offset) -> Option<S2SEventFrame> {
        let buffer_length = buffer.len();
        if offset.offset + 4 > buffer_length as i32 {
            return None;
        }
        let r = match self.read_uint32_be(buffer, offset.offset) {
            Ok(value) => {
                value
            }
            Err(_err) => {
                return None
            }
        };
        let s = offset.offset + r as i32 + 4;
        if (buffer_length as i32) < s {
            debug!("Second check :: Buffer length exceeds buffer length");
        }
        offset.end = s;
        offset.advance(4);
        let i = self.read_uint32_be(buffer, offset.offset).unwrap();
        offset.advance(4);

        let zlib_magic_number_0 = buffer[offset.offset as usize];
        let zlib_magic_number_1 = buffer[offset.offset as usize + 1usize];

        if zlib_magic_number_0 == ZLIB_MAGIC_NUMBERS_0 && zlib_magic_number_1 == ZLIB_MAGIC_NUMBERS_1 {
            debug!("failed handshake");
            return None;
        }

        let mut s2s_event = S2SEventFrame::default();

        for _ in 0..i {
            let x = self.read_uint32_be(buffer, offset.offset).unwrap();
            offset.advance(4);
            let mark = offset.offset;
            offset.advance(x as i32);
            let s = self.read_uint32_be(buffer, offset.offset).unwrap();
            offset.advance(4);
            self.set_s2s_field(buffer, &mut s2s_event, mark, x as i32, offset.offset, s as i32);
            offset.advance(s as i32);
        }

        self.validate_trailer_bullshit(buffer, offset, s);
        offset.offset = s;
        Some(s2s_event)
    }

    fn set_s2s_field(&mut self, buffer: &mut BytesMut, s2s_event: &mut S2SEventFrame, t: i32, r: i32, s: i32, i: i32) {
        let mut n = 0;
        if r > 5 {
            n = self.read_uint32_be(buffer, t).unwrap();
        }
        let x = self.read_uint32_be(buffer, t + r - 4 - 1).unwrap();
        let o = x ^ n;
        match o {
            1601331575 => {
                s2s_event.raw = self.read_str(buffer, s, i);
            }
            723321864 => {
                // s2s_event.time = self.read_ascii_
            }
            824770572 => {
                s2s_event.index = self.read_str(buffer, s, i);
            }
            84543253 => {
                let host_prefix_length = "host::".len() as i32;
                s2s_event.host = self.read_str(buffer, s + host_prefix_length, i - host_prefix_length);
            }
            941037316 => {
                let source_prefix_length = "source::".len() as i32;
                s2s_event.source = self.read_str(buffer, s + source_prefix_length, i - source_prefix_length);
            }
            958137348 => {
                let source_type_prefix_length = "sourcetype::".len() as i32;
                s2s_event.sourcetype = self.read_str(buffer, s + source_type_prefix_length, i - source_type_prefix_length);
            }
            824916566 => {
                let key = String::from("__s2s_eventId");
                let value = self.read_str(buffer, s, i);
                s2s_event.control_fields.insert(key.clone(), value.clone());
            }
            724964929 => {
                let key = String::from("__s2s_capabilities");
                let value = self.read_str(buffer, s, i);
                s2s_event.control_fields.insert(key.clone(), value.clone());
            }
            _ => {
                let key = self.read_str(buffer, t, r);
                let value = self.read_str(buffer, s, i);
                s2s_event.control_fields.insert(key.clone(), value.clone());
            }
        }
    }

    fn validate_trailer_bullshit(&mut self, buffer: &mut BytesMut, offset: &mut Offset, t: i32) {
        let r = self.read_uint32_be(buffer, offset.offset).unwrap();
        offset.advance(4);
        if r != 0 {
            debug!("Expected to find 4 zeroed out bytes; found: {}", r)
        }
        let s = self.read_uint32_be(buffer, offset.offset).unwrap();
        offset.advance(4 + s as i32);
        if offset.offset != t {
            let x = self.read_str(buffer, offset.offset, t - offset.offset);
            debug!("expected to have read {}; read: {} with remaining {}", t, offset.offset, x)
        }
    }

    fn read_uint32_be(&mut self, buffer: &mut BytesMut, offset: i32) -> Result<u32, String> {
        // let buffer = buffer;
        // Extract 4 bytes starting from the given offset
        let start = offset;
        let end = offset + 4;
        if end as usize >= buffer.len() {
            return Err(format!("Insufficient bytes to read u32 at offset {}: required {} but got {}", offset, 4, buffer.len() - start as usize));
        }
        let bytes = &buffer[start as usize..end as usize];
        // Convert the 4 bytes to a 32-bit integer using big-endian ordering
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn flag(number: i32) -> Vec<u8> {
        let mut buffer = Vec::new();
        if number != 0 {
            buffer.extend(&number.to_be_bytes());
        }
        buffer
    }

    fn fields() -> IndexMap<String, String> {
        let mut fields = IndexMap::new();
        fields.insert("cap_response".to_string(), "success".to_string());
        fields.insert("cap_flush_key".to_string(), "false".to_string());
        fields.insert("idx_can_send_hb".to_string(), "false".to_string());
        fields.insert("idx_can_recv_token".to_string(), "false".to_string());
        fields.insert("v4".to_string(), "true".to_string());
        fields.insert("channel_limit".to_string(), "300".to_string());
        fields.insert("pl".to_string(), "6".to_string());
        fields
    }

    fn get_s2s_signature(&self) -> Vec<u8> {
        let control = Self::flag(1);

        let intro_message = "__s2s_control_msg";
        let intro_size = intro_message.len() + 1; // +1 for null terminator
        let intro_control = Self::flag(intro_size as i32);
        let mut intro_buffer = Vec::with_capacity(intro_size);
        intro_buffer.extend(intro_message.as_bytes());
        intro_buffer.push(0); // Explicitly add a null terminator

        let fields_text: String = Self::fields()
            .into_iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<String>>()
            .join(";");

        let fields_size = fields_text.len() + 1; // +1 for null terminator
        let fields_control = Self::flag(fields_size as i32);
        let mut fields_buffer = Vec::with_capacity(fields_size);
        fields_buffer.extend(fields_text.as_bytes());
        fields_buffer.push(0);
        fields_buffer.push(0); //
        fields_buffer.push(0); //
        fields_buffer.push(0); //
        fields_buffer.push(0); // Explicitly add a null terminator

        let end_control = Self::flag(0);

        let format = "_raw";
        let format_size = format.len() + 1; // +1 for null terminator
        let format_control = Self::flag(format_size as i32);
        let mut format_buffer = Vec::with_capacity(format_size);
        format_buffer.extend(format.as_bytes());
        format_buffer.push(0); // Explicitly add a null terminator

        // Calculate total payload size, including all components
        let capacity = control.len()
            + intro_control.len()
            + intro_buffer.len()
            + fields_control.len()
            + fields_buffer.len()
            + end_control.len()
            + format_control.len()
            + format_buffer.len();

        let size_control = Self::flag(capacity as i32);

        // Assemble the final payload
        let mut payload = Vec::with_capacity(capacity + size_control.len());
        payload.extend(size_control);
        payload.extend(control);
        payload.extend(intro_control);
        payload.extend(intro_buffer);
        payload.extend(fields_control);
        payload.extend(fields_buffer);
        payload.extend(end_control);
        payload.extend(format_control);
        payload.extend(format_buffer);

        payload
    }

    fn read_u8(&mut self, buffer: &mut BytesMut, offset: usize) -> u8 {
        buffer.get(offset).copied().unwrap() // Safely get the byte at the offset
    }
}


#[derive(Debug)]
struct Channel {
    channel_id: i32,
    value_1: String,
    key_1: String,
    extra: String,
    headers: Vec<String>,
    metadata: HashMap<String, String>,
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Channel {{\n  channel_id: {},\n  value_1: \"{}\",\n  key_1: \"{}\",\n  extra: \"{}\",\n  headers: {:?},\n  metadata: {:?}\n}}",
            self.channel_id,
            self.value_1,
            self.key_1,
            self.extra,
            self.headers,
            self.metadata
        )
    }
}

#[derive(Debug, Clone)]
struct FwdHeader {
    _signature: String,
    _server_name: String,
    _port: i32,
}

#[derive(Debug, Clone)]
struct FwdInfo {
    _capabilities: HashMap<String, String>,
    _s2s_token: String,
    _forwarder_info: HashMap<String, String>,
}

struct Offset {
    end: i32,
    offset: i32,
    throw_exception_on_overflow: bool,
}

impl Offset {
    fn new(offset: i32) -> Offset {
        Offset {
            offset,
            end: 0,
            throw_exception_on_overflow: false,
        }
    }

    fn new_(offset: i32, throw_exception_on_overflow: bool) -> Offset {
        Offset {
            offset,
            end: 0,
            throw_exception_on_overflow,
        }
    }

    fn advance(&mut self, n: i32) -> i32 {
        let curr_offset = self.offset;
        self.offset += n;
        if (self.offset > self.end) && (self.throw_exception_on_overflow) {
            return -1;
        }
        curr_offset
    }
}


#[derive(Debug, Clone)]
pub(crate) struct S2SEventFrame {
    data_size: i32,
    done: bool,
    channel: Option<i32>,
    source: String,
    sourcetype: String,
    host: String,
    time: i64,
    payload_type: PayloadType,
    raw: String,
    is_broken: bool,
    broken_event_count: i32,
    fields: HashMap<String, Vec<String>>,
    buf: Vec<u8>,
    flags: String,
    breaker_fields: Vec<String>,
    control_fields: HashMap<String, String>,
    fin: bool,
    __s2s_id: Option<i32>, // should move to option
    num_fields: i32,
    command: Option<Command>,
    index: String,
    fwd_type: String,
    s2s_token: String,
    version: Option<String>,

    // header fields
    pub(crate) header_buffer: Option<Vec<u8>>,
    fwd_header: Option<FwdHeader>,

    // fwd_capabilities fields
    capabilities_map: Option<HashMap<String, String>>,

    // fwd_info fields
    fwd_info: Option<FwdInfo>
}

impl Default for S2SEventFrame {
    fn default() -> Self {
        S2SEventFrame {
            channel: None,
            data_size: 0,
            done: true,
            index: String::from(""),
            source: String::from(""),
            sourcetype: String::from(""),
            host: String::from(""),
            time: 0,
            payload_type: PayloadType::Unknown,
            raw: String::from(""),
            is_broken: false,
            fields: HashMap::new(),
            control_fields: HashMap::new(),
            flags: String::new(),
            breaker_fields: Vec::new(),
            fin: false,
            broken_event_count: 0,
            __s2s_id: None,
            num_fields: 0,
            buf: Vec::new(),
            command: None,
            fwd_type: String::from(""),
            s2s_token: String::from(""),
            version: None,
            capabilities_map:None,
            header_buffer: None,
            fwd_header: None,
            fwd_info: None,
        }
    }
}
impl fmt::Display for S2SEventFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S2SEVENT {{\n")?;
        write!(f, "  channel: {:?},\n", self.channel)?;
        write!(f, "  source: \"{}\",\n", self.source)?;
        write!(f, "  sourcetype: \"{}\",\n", self.sourcetype)?;
        write!(f, "  host: \"{}\",\n", self.host)?;
        write!(f, "  _s2s_id: \"{:?}\",\n", self.__s2s_id)?;
        write!(f, "  fwd_type: \"{}\",\n", self.fwd_type)?;
        write!(f, "  s2s_token: \"{}\",\n", self.s2s_token)?;


        write!(f, "  payload: {:?},\n", self.payload_type)?;
        write!(f, "  command: {:?},\n", self.command)?;
        write!(f, "  data_size: {:?},\n", self.data_size)?;

        write!(f, "  time: {:?},\n", self.time)?;

        write!(f, "  raw: \"{}\",\n", self.raw)?;

        write!(f, "  is_broken: {},\n", self.is_broken)?;
        write!(f, "  broken_event_count: {},\n", self.broken_event_count)?;

        write!(f, "  fields: {{")?;
        for (key, value) in &self.fields {
            write!(f, " \"{}\": {:?},", key, value)?;
        }
        write!(f, " }},\n")?;

        write!(f, "  control_fields: {{")?;
        for (key, value) in &self.control_fields {
            write!(f, " \"{}\": {},", key, value)?;
        }
        write!(f, " }},\n")?;

        write!(f, "  flags: \"{}\",\n", self.flags)?;

        write!(f, "  breaker_fields: {:?},\n", self.breaker_fields)?;

        write!(f, "  fin: {}\n", self.fin)?;
        write!(f, "  done: {}\n", self.done)?;

        let ascii_string: String = self.buf.iter().map(|&byte| byte as char).collect();
        write!(f, "  ascii_string: {},\n", ascii_string)?;


        // let formatted_bytes: Vec<String> = self.buf.iter().map(|byte| format!("0x{:02X}", byte)).collect();
        // write!(f, "[{}]\n", formatted_bytes.join(", ")).expect("TODO: panic message");

        write!(f, "}}")?;

        Ok(())
    }
}

impl S2SEventFrame {
    pub(crate) fn get_log_event(&self) -> LogEvent {
        let source_value = Value::from(self.source.clone());
        let source_type_value = Value::from(self.sourcetype.clone());
        let host_value = Value::from(self.host.clone());
        let timestamp_value = Value::from(self.time);
        let message_value = Value::from(self.raw.clone());
        let fields_value = Value::from(
            self.fields.clone().into_iter()
                .map(|(key, value)| (key, Value::from(value)))
                .collect::<BTreeMap<_, _>>()
        );
        let control_fields_value = Value::from(
            self.control_fields.clone().into_iter()
                .map(|(key, value)| (key, Value::from(value)))
                .collect::<BTreeMap<_, _>>()
        );
        let mut log = BTreeMap::new();
        log.insert("source".to_string(), source_value);
        log.insert("sourcetype".to_string(), source_type_value);
        log.insert("host".to_string(), host_value);
        log.insert("event_timestamp".to_string(), timestamp_value);
        log.insert("message".to_string(), message_value);
        log.insert("fields".to_string(), fields_value);
        log.insert("control_fields".to_string(), control_fields_value);
        LogEvent::from(log)
    }
    fn _read_uint32_be(&mut self, offset: i32) -> Result<u32, String> {
        let buffer = &self.buf;
        // Extract 4 bytes starting from the given offset
        let start = offset;
        let end = offset + 4;
        if end as usize >= self.buf.len() {
            return Err(format!("Insufficient bytes to read u32 at offset {}: required {} but got {}", offset, 4, buffer.len() - start as usize));
        }
        let bytes = &buffer[start as usize..end as usize];
        // Convert the 4 bytes to a 32-bit integer using big-endian ordering
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }
}

struct ObjectData {
    key: String,
    _raw_offset: i32,
    _length: i32,
    _flag: FieldAction,
}

struct KeyTypeData {
    key: String,
    _index: i32,
    num_type: String,
    flag: FieldAction,
    precision: i32,
    _scale: i32,
}


// constants

const THREE: u32 = 3;
const ZLIB_MAGIC_NUMBERS_0: u8 = 120;
const ZLIB_MAGIC_NUMBERS_1: u8 = 156;
const FWD_HEADER_MIN_LENGTH: usize = 400;

const PREDEFINED_KV_STRINGS: [&str; 50] = [
    "_subsecond", "date_second", "date_minute", "date_hour",
    "date_year", "date_month", "date_mday", "date_wday",
    "date_zone", "sunday", "monday", "tuesday", "wednesday",
    "thursday", "friday", "saturday", "january", "february",
    "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "local",
    "punct", "timestartpos", "timeendpos", "_indextime",
    "meta", "truncated", "timestamp", "invalid",
    "none", "eet", "elt", "ert", "iet", "ilt", "usz",
    "nev", "nh", "ns", "nst", "nstr", "null"
];

const PREDEFINED_KV_NUMBERS: [i32; 11] = [
    -60, -120, -180, -240, -300, -360, -420, -480, -540, -600, -660
];

const PREDEFINED_KV_BOOLEANS: [bool; 2] = [false, true];

fn get_key_from_predefined_strings(mut l: usize) -> String {
    // Check if `l` falls within the range of `PREDEFINED_KV_STRINGS`
    if l < PREDEFINED_KV_STRINGS.len() {
        return PREDEFINED_KV_STRINGS[l].to_string();
    }

    // Subtract the length of `PREDEFINED_KV_STRINGS`
    l -= PREDEFINED_KV_STRINGS.len();

    // Check if `l` falls within the range of `PREDEFINED_KV_NUMBERS`
    if l < PREDEFINED_KV_NUMBERS.len() {
        return PREDEFINED_KV_NUMBERS[l].to_string();
    }

    // Subtract the length of `PREDEFINED_KV_NUMBERS`
    l -= PREDEFINED_KV_NUMBERS.len();

    // Check if `l` falls within the range of `PREDEFINED_KV_BOOLEANS`
    PREDEFINED_KV_BOOLEANS[l].to_string()
}

// enums

#[derive(Debug, Clone, PartialEq)]
enum PayloadType {
    LogDataPacket = 63,
    LogData64KReplayPacket = 2111,
    LogEmptyPacket = 565,
    LogEmptySecondPacket = 1589,
    ScriptedInputPacket = 39,
    ScriptedEmptyPacket = 519,
    NetworkInputEmptyPacket = 551,
    SplunkInternalPacket = 525,
    FschangemonitorEmptyPacket = 533,
    WindowsEventlogPacket = 767,
    WindowsEventlogEmptyPacket = 735,
    WindowsEventlogSecondEmptyPacket = 1759,
    // SplunkWindowsSplunkdPacket = 2111,
    SplunkStderrLogEmptyPacket = 575,
    SplunkConfLogPacket = 639,
    SplunkConfLogSecondPacket = 17023,
    SplunkConfEmptyPacket = 629,
    SplunkEmptyPacket = 1557,
    SplunkMetricsEmptyLogPacket = 1087,
    SplunkMetricsEmptyLogSecondPacket = 3135,
    SplunkIntrospectionLogPacket = 37,
    SplunkIntrospectionLogEmptyPacket = 517,
    SplunkWineventlogAuthInfoEmptyPacket = 1791,
    SplunkWineventlogAuthInfoEmptySecondPacket = 1543,
    SplunkEmptySecondPacket = 1029,
    SplunkSplunkdEmptyPacket = 1919,
    HfLogFirstDataPacket = 895,
    HfLogSubsequentDataPacket = 17279,
    HfLogEmptyPacket = 885,
    HfLogEmptySecondPacket = 1653,
    HfLogEmptyThirdPacket = 17269,
    HfLogEmptyFourthPacket = 17013,
    HfScriptedInputFirstDataPacket = 879,
    HfScriptedInputSecondDataPacket = 17263,
    HfScriptedEmptyPacket = 1631,
    HfScriptedEmptySecondPacket = 1607,
    HfWineventlogEmptyPacket = 863,
    HfWineventlogSecondEmptyPacket = 839,
    HfAuditDataPacket = 591,
    HfAuditSecondDataPacket = 847,
    HfAuditEmptyPacket = 1615,
    HfIntrospectionLogPacket = 66431,
    HfIntrospectionEmptyPacket = 837,
    HfSplunkEmptyPacket = 853,
    HfInternalMetricDataPacket = 82815,
    HfInternalMetricEmptyPacket = 18047,
    HfAuditLogDataPacket = 201551,
    SplunkNetworkSslPacket = 589,
    SplunkNetworkSslThirdPacket = 17277,
    SplunkNetworkSslSecondPacket = 581,
    SplunkNetworkSslEmptyPacket = 1613,
    SplunkNetworkSslEmptySecondPacket = 1621,
    SplunkNetworkSslEmptyThirdPacket = 1605,
    SplunkNetworkSslEmptyFourthPacket = 1629,
    SplunkCookedSyslogSslPacket = 2623,
    SplunkCustomSyslog = 4943,
    SplunkTeleappEmptyPacket = 5711,
    SplunkKubernetesPacket = 21359,
    SplunkKubernetesSecondPacket = 4975,
    SplunkKubernetesThirdPacket = 22127,
    SplunkPsScriptedInputPacket = 2087,
    SplunkPsScriptedEmptyPacket = 1063,
    SplunkLogEmptyPacket = 1599,
    SplunkEmptyUnknownPacket = 18031,
    SplunkEmptyUnknownSecondPacket = 1647,
    SplunkTeleversionEmptyPacket = 845,
    SplunkWindowsInternalMetricsLogEmptyPacket = 1663,
    SplunkWindowsSplunkdEmptyPacket = 1909,
    Unknown = 0,
}

impl PayloadType {
    pub fn of(payload_value: i32) -> PayloadType {
        match payload_value {
            63 => PayloadType::LogDataPacket,
            2111 => PayloadType::LogData64KReplayPacket,
            565 => PayloadType::LogEmptyPacket,
            1589 => PayloadType::LogEmptySecondPacket,
            39 => PayloadType::ScriptedInputPacket,
            519 => PayloadType::ScriptedEmptyPacket,
            551 => PayloadType::NetworkInputEmptyPacket,
            525 => PayloadType::SplunkInternalPacket,
            533 => PayloadType::FschangemonitorEmptyPacket,
            767 => PayloadType::WindowsEventlogPacket,
            735 => PayloadType::WindowsEventlogEmptyPacket,
            1759 => PayloadType::WindowsEventlogSecondEmptyPacket,
            // 2111 => PayloadType::SplunkWindowsSplunkdPacket,
            575 => PayloadType::SplunkStderrLogEmptyPacket,
            639 => PayloadType::SplunkConfLogPacket,
            17023 => PayloadType::SplunkConfLogSecondPacket,
            629 => PayloadType::SplunkConfEmptyPacket,
            1557 => PayloadType::SplunkEmptyPacket,
            1087 => PayloadType::SplunkMetricsEmptyLogPacket,
            3135 => PayloadType::SplunkMetricsEmptyLogSecondPacket,
            37 => PayloadType::SplunkIntrospectionLogPacket,
            517 => PayloadType::SplunkIntrospectionLogEmptyPacket,
            1791 => PayloadType::SplunkWineventlogAuthInfoEmptyPacket,
            1543 => PayloadType::SplunkWineventlogAuthInfoEmptySecondPacket,
            1029 => PayloadType::SplunkEmptySecondPacket,
            1919 => PayloadType::SplunkSplunkdEmptyPacket,
            895 => PayloadType::HfLogFirstDataPacket,
            17279 => PayloadType::HfLogSubsequentDataPacket,
            885 => PayloadType::HfLogEmptyPacket,
            1653 => PayloadType::HfLogEmptySecondPacket,
            17269 => PayloadType::HfLogEmptyThirdPacket,
            17013 => PayloadType::HfLogEmptyFourthPacket,
            879 => PayloadType::HfScriptedInputFirstDataPacket,
            17263 => PayloadType::HfScriptedInputSecondDataPacket,
            1631 => PayloadType::HfScriptedEmptyPacket,
            1607 => PayloadType::HfScriptedEmptySecondPacket,
            863 => PayloadType::HfWineventlogEmptyPacket,
            839 => PayloadType::HfWineventlogSecondEmptyPacket,
            591 => PayloadType::HfAuditDataPacket,
            847 => PayloadType::HfAuditSecondDataPacket,
            1615 => PayloadType::HfAuditEmptyPacket,
            66431 => PayloadType::HfIntrospectionLogPacket,
            837 => PayloadType::HfIntrospectionEmptyPacket,
            853 => PayloadType::HfSplunkEmptyPacket,
            82815 => PayloadType::HfInternalMetricDataPacket,
            18047 => PayloadType::HfInternalMetricEmptyPacket,
            201551 => PayloadType::HfAuditLogDataPacket,
            589 => PayloadType::SplunkNetworkSslPacket,
            17277 => PayloadType::SplunkNetworkSslThirdPacket,
            581 => PayloadType::SplunkNetworkSslSecondPacket,
            1613 => PayloadType::SplunkNetworkSslEmptyPacket,
            1621 => PayloadType::SplunkNetworkSslEmptySecondPacket,
            1605 => PayloadType::SplunkNetworkSslEmptyThirdPacket,
            1629 => PayloadType::SplunkNetworkSslEmptyFourthPacket,
            2623 => PayloadType::SplunkCookedSyslogSslPacket,
            4943 => PayloadType::SplunkCustomSyslog,
            5711 => PayloadType::SplunkTeleappEmptyPacket,
            21359 => PayloadType::SplunkKubernetesPacket,
            4975 => PayloadType::SplunkKubernetesSecondPacket,
            22127 => PayloadType::SplunkKubernetesThirdPacket,
            2087 => PayloadType::SplunkPsScriptedInputPacket,
            1063 => PayloadType::SplunkPsScriptedEmptyPacket,
            1599 => PayloadType::SplunkLogEmptyPacket,
            18031 => PayloadType::SplunkEmptyUnknownPacket,
            1647 => PayloadType::SplunkEmptyUnknownSecondPacket,
            845 => PayloadType::SplunkTeleversionEmptyPacket,
            1663 => PayloadType::SplunkWindowsInternalMetricsLogEmptyPacket,
            1909 => PayloadType::SplunkWindowsSplunkdEmptyPacket,
            _ => PayloadType::Unknown,
        }
    }

    pub fn is(payload_value: i32) -> bool {
        match payload_value {
            63 | 2111 | 565 | 1589 | 39 | 519 | 551 | 525 | 533 | 767 | 735 | 1759 | 575 | 639 | 17023 | 629 | 1557 | 1087 | 3135 | 37 | 517 | 1791 | 1543 | 1029 | 1919 | 895 | 17279 | 885 | 1653 | 17269 | 17013 | 879 | 17263 | 1631 | 1607 | 863 | 839 | 591 | 847 | 1615 | 66431 | 837 | 853 | 82815 | 18047 | 201551 | 589 | 17277 | 581 | 1613 | 1621 | 1605 | 1629 | 2623 | 4943 | 5711 | 21359 | 4975 | 22127 | 2087 | 1063 | 1599 | 18031 | 1647 | 845 | 1663 | 1909 => true,
            _ => false,
        }
    }
}

#[derive(Debug, Snafu)]
pub(crate) enum S2SDecoderError {
    #[snafu(display("i/o error: {}", source))]
    IO { source: io::Error },

    #[snafu(display("Unknown OpCode: {}", opcode))]
    UnexpectedOpCode { opcode: u8 },

    #[snafu(display("Unknown Channel ID: {}", channel_id))]
    UnknownChannel { channel_id: u64 },

    #[snafu(display("Invalid data encoding"))]
    InvalidDataEncoding,

    #[snafu(display("Buffer overflow"))]
    BufferOverflow,

    #[snafu(display("Not Enough Data"))]
    InSufficientData,

    #[snafu(display("Decoder error: {}", message))]
    GenericError { message: String },
}


impl StreamDecodingError for S2SDecoderError {
    fn can_continue(&self) -> bool {
        match self {
            S2SDecoderError::IO { .. } => false,
            S2SDecoderError::UnexpectedOpCode { .. } => false,
            S2SDecoderError::UnknownChannel { .. } => false,
            S2SDecoderError::InvalidDataEncoding => false,
            S2SDecoderError::BufferOverflow => true,
            S2SDecoderError::InSufficientData => true,
            S2SDecoderError::GenericError { .. } => false,
            // _ => false,
        }
    }
}

impl From<io::Error> for S2SDecoderError {
    fn from(source: io::Error) -> Self {
        S2SDecoderError::IO { source }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)] // Ensure each variant is stored as a `u8` in memory
enum Command {
    CloneChannel = 0xF8,
    Compressed = 0xF9,
    AckRange = 0xFA,
    Ack = 0xFB,
    ReadEvent = 0xFC,
    AbandonChannel = 0xFD,
    RegisterChannel = 0xFE,
    Timezone = 0xFF,
}

impl Command {
    /// Convert a `u8` to a `Command` (similar to "reverse lookup")
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0xF8 => Some(Command::CloneChannel),
            0xF9 => Some(Command::Compressed),
            0xFA => Some(Command::AckRange),
            0xFB => Some(Command::Ack),
            0xFC => Some(Command::ReadEvent),
            0xFD => Some(Command::AbandonChannel),
            0xFE => Some(Command::RegisterChannel),
            0xFF => Some(Command::Timezone),
            _ => None, // If it's not one of the defined values, return None
        }
    }

    fn is_command(value: u8) -> bool {
        match value {
            0xF8 => true,
            0xF9 => true,
            0xFA => true,
            0xFB => true,
            0xFC => true,
            0xFD => true,
            0xFE => true,
            0xFF => true,
            _ => false, // If it's not one of the defined values, return None
        }
    }

    /// Return all possible commands as an array
    fn _all_commands() -> &'static [Command] {
        &[
            Command::CloneChannel,
            Command::Compressed,
            Command::AckRange,
            Command::Ack,
            Command::ReadEvent,
            Command::AbandonChannel,
            Command::RegisterChannel,
            Command::Timezone,
        ]
    }

    /// Return all possible command codes as an array
    fn _all_command_codes() -> &'static [u8] {
        &[
            Command::CloneChannel as u8,
            Command::Compressed as u8,
            Command::AckRange as u8,
            Command::Ack as u8,
            Command::ReadEvent as u8,
            Command::AbandonChannel as u8,
            Command::RegisterChannel as u8,
            Command::Timezone as u8,
        ]
    }
}

struct EventFlags;
impl EventFlags {
    const RAW: i32 = 1;
    const SOURCE_METADATA: i32 = 2;
    const EVENT_ID: i32 = 4;
    const TIME: i32 = 8;
    const BROKEN: i32 = 64;
    const LAST_EVENT: i32 = 512;
    const DOUBLES: i32 = 65536;
}

#[repr(u32)]
enum FieldAction {
    KeepTop = 1,
    KeepCtrl = 2,
    DROP = 4,
}
impl FieldAction {
    pub fn value(&self) -> u32 {
        match *self {
            FieldAction::KeepTop => 1,
            FieldAction::KeepCtrl => 2,
            FieldAction::DROP => 4,
        }
    }

    pub fn clone(&self) -> FieldAction {
        match *self {
            FieldAction::KeepTop => FieldAction::KeepTop,
            FieldAction::KeepCtrl => FieldAction::KeepCtrl,
            FieldAction::DROP => FieldAction::DROP
        }
    }
}


fn to_precision(n: f64, precision: usize) -> f64 {
    let precision = std::cmp::min(precision, 100); // Ensure precision doesn't exceed 100
    let formatted = format!("{:.*}", precision, n);  // Format the number to the required precision
    formatted.parse().unwrap_or(0.0) // Parse it back to f64, default to 0.0 on error
}