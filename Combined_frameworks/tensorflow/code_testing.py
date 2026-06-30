import tensorflow as tf

input_t = tf.constant([1, 2, 3], shape=[3], dtype=tf.int32)
value = None
tf.raw_ops.StatusExtractVariantFromInput(input_t, 0, value)