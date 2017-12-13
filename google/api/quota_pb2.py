# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: google/api/quota.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.api import annotations_pb2 as google_dot_api_dot_annotations__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='google/api/quota.proto',
  package='google.api',
  syntax='proto3',
  serialized_pb=_b('\n\x16google/api/quota.proto\x12\ngoogle.api\x1a\x1cgoogle/api/annotations.proto\"]\n\x05Quota\x12&\n\x06limits\x18\x03 \x03(\x0b\x32\x16.google.api.QuotaLimit\x12,\n\x0cmetric_rules\x18\x04 \x03(\x0b\x32\x16.google.api.MetricRule\"\x91\x01\n\nMetricRule\x12\x10\n\x08selector\x18\x01 \x01(\t\x12=\n\x0cmetric_costs\x18\x02 \x03(\x0b\x32\'.google.api.MetricRule.MetricCostsEntry\x1a\x32\n\x10MetricCostsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x03:\x02\x38\x01\"\x95\x02\n\nQuotaLimit\x12\x0c\n\x04name\x18\x06 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x02 \x01(\t\x12\x15\n\rdefault_limit\x18\x03 \x01(\x03\x12\x11\n\tmax_limit\x18\x04 \x01(\x03\x12\x11\n\tfree_tier\x18\x07 \x01(\x03\x12\x10\n\x08\x64uration\x18\x05 \x01(\t\x12\x0e\n\x06metric\x18\x08 \x01(\t\x12\x0c\n\x04unit\x18\t \x01(\t\x12\x32\n\x06values\x18\n \x03(\x0b\x32\".google.api.QuotaLimit.ValuesEntry\x12\x14\n\x0c\x64isplay_name\x18\x0c \x01(\t\x1a-\n\x0bValuesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x03:\x02\x38\x01\x42l\n\x0e\x63om.google.apiB\nQuotaProtoP\x01ZEgoogle.golang.org/genproto/googleapis/api/serviceconfig;serviceconfig\xa2\x02\x04GAPIb\x06proto3')
  ,
  dependencies=[google_dot_api_dot_annotations__pb2.DESCRIPTOR,])




_QUOTA = _descriptor.Descriptor(
  name='Quota',
  full_name='google.api.Quota',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='limits', full_name='google.api.Quota.limits', index=0,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='metric_rules', full_name='google.api.Quota.metric_rules', index=1,
      number=4, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
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
  serialized_start=68,
  serialized_end=161,
)


_METRICRULE_METRICCOSTSENTRY = _descriptor.Descriptor(
  name='MetricCostsEntry',
  full_name='google.api.MetricRule.MetricCostsEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='google.api.MetricRule.MetricCostsEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='value', full_name='google.api.MetricRule.MetricCostsEntry.value', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=_descriptor._ParseOptions(descriptor_pb2.MessageOptions(), _b('8\001')),
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=259,
  serialized_end=309,
)

_METRICRULE = _descriptor.Descriptor(
  name='MetricRule',
  full_name='google.api.MetricRule',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='selector', full_name='google.api.MetricRule.selector', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='metric_costs', full_name='google.api.MetricRule.metric_costs', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[_METRICRULE_METRICCOSTSENTRY, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=164,
  serialized_end=309,
)


_QUOTALIMIT_VALUESENTRY = _descriptor.Descriptor(
  name='ValuesEntry',
  full_name='google.api.QuotaLimit.ValuesEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='google.api.QuotaLimit.ValuesEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='value', full_name='google.api.QuotaLimit.ValuesEntry.value', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=_descriptor._ParseOptions(descriptor_pb2.MessageOptions(), _b('8\001')),
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=544,
  serialized_end=589,
)

_QUOTALIMIT = _descriptor.Descriptor(
  name='QuotaLimit',
  full_name='google.api.QuotaLimit',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='google.api.QuotaLimit.name', index=0,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='description', full_name='google.api.QuotaLimit.description', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='default_limit', full_name='google.api.QuotaLimit.default_limit', index=2,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='max_limit', full_name='google.api.QuotaLimit.max_limit', index=3,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='free_tier', full_name='google.api.QuotaLimit.free_tier', index=4,
      number=7, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='duration', full_name='google.api.QuotaLimit.duration', index=5,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='metric', full_name='google.api.QuotaLimit.metric', index=6,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='unit', full_name='google.api.QuotaLimit.unit', index=7,
      number=9, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='values', full_name='google.api.QuotaLimit.values', index=8,
      number=10, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='display_name', full_name='google.api.QuotaLimit.display_name', index=9,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[_QUOTALIMIT_VALUESENTRY, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=312,
  serialized_end=589,
)

_QUOTA.fields_by_name['limits'].message_type = _QUOTALIMIT
_QUOTA.fields_by_name['metric_rules'].message_type = _METRICRULE
_METRICRULE_METRICCOSTSENTRY.containing_type = _METRICRULE
_METRICRULE.fields_by_name['metric_costs'].message_type = _METRICRULE_METRICCOSTSENTRY
_QUOTALIMIT_VALUESENTRY.containing_type = _QUOTALIMIT
_QUOTALIMIT.fields_by_name['values'].message_type = _QUOTALIMIT_VALUESENTRY
DESCRIPTOR.message_types_by_name['Quota'] = _QUOTA
DESCRIPTOR.message_types_by_name['MetricRule'] = _METRICRULE
DESCRIPTOR.message_types_by_name['QuotaLimit'] = _QUOTALIMIT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Quota = _reflection.GeneratedProtocolMessageType('Quota', (_message.Message,), dict(
  DESCRIPTOR = _QUOTA,
  __module__ = 'google.api.quota_pb2'
  # @@protoc_insertion_point(class_scope:google.api.Quota)
  ))
_sym_db.RegisterMessage(Quota)

MetricRule = _reflection.GeneratedProtocolMessageType('MetricRule', (_message.Message,), dict(

  MetricCostsEntry = _reflection.GeneratedProtocolMessageType('MetricCostsEntry', (_message.Message,), dict(
    DESCRIPTOR = _METRICRULE_METRICCOSTSENTRY,
    __module__ = 'google.api.quota_pb2'
    # @@protoc_insertion_point(class_scope:google.api.MetricRule.MetricCostsEntry)
    ))
  ,
  DESCRIPTOR = _METRICRULE,
  __module__ = 'google.api.quota_pb2'
  # @@protoc_insertion_point(class_scope:google.api.MetricRule)
  ))
_sym_db.RegisterMessage(MetricRule)
_sym_db.RegisterMessage(MetricRule.MetricCostsEntry)

QuotaLimit = _reflection.GeneratedProtocolMessageType('QuotaLimit', (_message.Message,), dict(

  ValuesEntry = _reflection.GeneratedProtocolMessageType('ValuesEntry', (_message.Message,), dict(
    DESCRIPTOR = _QUOTALIMIT_VALUESENTRY,
    __module__ = 'google.api.quota_pb2'
    # @@protoc_insertion_point(class_scope:google.api.QuotaLimit.ValuesEntry)
    ))
  ,
  DESCRIPTOR = _QUOTALIMIT,
  __module__ = 'google.api.quota_pb2'
  # @@protoc_insertion_point(class_scope:google.api.QuotaLimit)
  ))
_sym_db.RegisterMessage(QuotaLimit)
_sym_db.RegisterMessage(QuotaLimit.ValuesEntry)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n\016com.google.apiB\nQuotaProtoP\001ZEgoogle.golang.org/genproto/googleapis/api/serviceconfig;serviceconfig\242\002\004GAPI'))
_METRICRULE_METRICCOSTSENTRY.has_options = True
_METRICRULE_METRICCOSTSENTRY._options = _descriptor._ParseOptions(descriptor_pb2.MessageOptions(), _b('8\001'))
_QUOTALIMIT_VALUESENTRY.has_options = True
_QUOTALIMIT_VALUESENTRY._options = _descriptor._ParseOptions(descriptor_pb2.MessageOptions(), _b('8\001'))
# @@protoc_insertion_point(module_scope)
