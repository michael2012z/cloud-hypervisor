// Copyright 2021 Arm Limited (or its affiliates). All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//!
//! This module implements an flash device.
//!

use std::io::{Read, Seek, SeekFrom};
use std::result;
use std::sync::{Arc, Barrier};
use vm_device::BusDevice;

#[derive(Debug)]
pub enum Error {
    /// Unable to seek to image start.
    SeekImageStart,
    /// Unable to seek to image end.
    SeekImageEnd,
    /// Image too big.
    ImageTooBig,
    /// Unable to read image.
    ReadImage,
}
type Result<T> = result::Result<T, Error>;

pub struct Flash {
    start: u64,
    size: u64,
    buffer: Vec<u8>,
    read_only: bool,
}

impl Flash {
    pub fn new<F>(start: u64, size: u64, image: &mut F, read_only: bool) -> Result<Self>
    where
        F: Read + Seek,
    {
        let mut buffer: Vec<u8> = Vec::with_capacity(size as usize);

        let image_size = image
            .seek(SeekFrom::End(0))
            .map_err(|_| Error::SeekImageEnd)? as u64;

        if image_size > size {
            return Err(Error::ImageTooBig);
        }

        image
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::SeekImageStart)?;

        image
            .read_to_end(&mut buffer)
            .map_err(|_| Error::ReadImage)?;

        debug!(
            "Flash::new(): start = 0x{:x}, size = 0x{:x}, image_size = 0x{:x}, buffer.len = 0x{:x}",
            start,
            size,
            image_size,
            buffer.len()
        );

        Ok(Flash {
            start,
            size,
            buffer,
            read_only,
        })
    }
}

impl BusDevice for Flash {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        debug!("Flash read: offset {}, data length {}", offset, data.len());
        if offset + data.len() as u64 <= self.size {
            for i in 0..data.len() {
                data[i] = self.buffer[offset as usize + i];
            }
        } else {
            warn!(
                "Invalid Flash read: offset {}, data length {}",
                offset,
                data.len()
            );
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if self.read_only {
            warn!(
                "Writing to read-only Flash area, ignored : offset {}, data length {}",
                offset,
                data.len()
            );
        } else {
            debug!("Flash write: offset {}, data length {}", offset, data.len());
            if offset + data.len() as u64 <= self.size {
                for i in 0..data.len() {
                    self.buffer[offset as usize + i] = data[i];
                }
            } else {
                warn!(
                    "Invalid Flash write: offset {}, data length {}",
                    offset,
                    data.len()
                );
            }
        }
        None
    }
}
