const { hashPassword } = require('../../../lib/auth');
const { supabaseAdmin } = require('../../../lib/supabase');

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, newPassword } = req.body;

    // Validate required fields
    if (!email || !newPassword) {
      return res.status(400).json({ error: 'Email and new password are required' });
    }

    // Validate password length
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Find user by email
    const { data: users, error: findError } = await supabaseAdmin
      .from('users')
      .select('id, email')
      .eq('email', email)
      .limit(1);

    if (findError || !users || users.length === 0) {
      return res.status(404).json({ error: 'User not found with this email' });
    }

    const user = users[0];

    // Hash the new password
    const passwordHash = await hashPassword(newPassword);

    // Update password in database
    const { error: updateError } = await supabaseAdmin
      .from('users')
      .update({ password_hash: passwordHash })
      .eq('id', user.id);

    if (updateError) {
      console.error('Password update error:', updateError);
      return res.status(500).json({ error: 'Failed to update password' });
    }

    return res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
