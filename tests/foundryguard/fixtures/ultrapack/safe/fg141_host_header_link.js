async function forgotPassword(req, res) {
  const token = await createResetToken(req.body.email);
  const link = `${process.env.PUBLIC_BASE_URL}/reset?token=${token}`;
  await sendMail(req.body.email, link);
  res.sendStatus(202);
}

module.exports = { forgotPassword };
