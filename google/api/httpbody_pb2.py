# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: google/api/httpbody.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='google/api/httpbody.proto',
  package='google.api',
  syntax='proto3',
  serialized_pb=_b('\n\x19google/api/httpbody.proto\x12\ngoogle.api\".\n\x08HttpBody\x12\x14\n\x0c\x63ontent_type\x18\x01 \x01(\t\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\x42\x65\n\x0e\x63om.google.apiB\rHttpBodyProtoP\x01Z;google.golang.org/genproto/googleapis/api/httpbody;httpbody\xa2\x02\x04GAPIb\x06proto3')
)




_HTTPBODY = _descriptor.Descriptor(
  name='HttpBody',
  full_name='google.api.HttpBody',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='content_type', full_name='google.api.HttpBody.content_type', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data', full_name='google.api.HttpBody.data', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=41,
  serialized_end=87,
)

DESCRIPTOR.message_types_by_name['HttpBody'] = _HTTPBODY
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

HttpBody = _reflection.GeneratedProtocolMessageType('HttpBody', (_message.Message,), dict(
  DESCRIPTOR = _HTTPBODY,
  __module__ = 'google.api.httpbody_pb2'
  # @@protoc_insertion_point(class_scope:google.api.HttpBody)
  ))
_sym_db.RegisterMessage(HttpBody)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n\016com.google.apiB\rHttpBodyProtoP\001Z;google.golang.org/genproto/googleapis/api/httpbody;httpbody\242\002\004GAPI'))
# @@protoc_insertion_point(module_scope)
