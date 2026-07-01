import { 
  createClient, 
  SupabaseClient, 
  AuthError 
} from '@supabase/supabase-js';
import { Database } from '../types/database';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

export interface User {
  id: string;
  email: string;
  role: 'student' | 'department_head' | 'admin';
  created_at: string;
  updated_at: string;
}

export interface StudentProfile {
  student_id: string;
  user_id: string;
  full_name: string;
  email: string;
  department_id: string;
  enrollment_status: 'active' | 'inactive' | 'graduated' | 'suspended';
  created_at: string;
  updated_at: string;
}

export interface AuthResponse {
  success: boolean;
  user?: User | StudentProfile;
  error?: AuthError | Error | string;
  message?: string;
}

export interface SignUpData {
  email: string;
  password: string;
  fullName: string;
  department: string;
}

export interface UpdateProfileData {
  fullName?: string;
  enrollmentStatus?: 'active' | 'inactive' | 'graduated' | 'suspended';
}

// ============================================================================
// SUPABASE CLIENT INITIALIZATION
// ============================================================================

const supabaseUrl = process.env.REACT_APP_SUPABASE_URL || '';
const supabaseAnonKey = process.env.REACT_APP_SUPABASE_ANON_KEY || '';

export const supabase: SupabaseClient<Database> = createClient(
  supabaseUrl,
  supabaseAnonKey
);

// ============================================================================
// AUTHENTICATION SERVICE
// ============================================================================

/**
 * Sign up a new student
 * @param email Student email
 * @param password Password
 * @param fullName Student full name
 * @param department Department ID
 * @returns AuthResponse with user data or error
 */
export async function signUpStudent(
  email: string,
  password: string,
  fullName: string,
  department: string
): Promise<AuthResponse> {
  try {
    // Validate inputs
    if (!email || !password || !fullName || !department) {
      return {
        success: false,
        error: 'All fields are required',
        message: 'Missing required fields'
      };
    }

    if (password.length < 8) {
      return {
        success: false,
        error: 'Password must be at least 8 characters',
        message: 'Password too short'
      };
    }

    // Create auth user
    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: fullName,
          role: 'student'
        }
      }
    });

    if (authError) {
      return {
        success: false,
        error: authError,
        message: 'Failed to create account'
      };
    }

    if (!authData.user) {
      return {
        success: false,
        error: 'User creation failed',
        message: 'No user returned from signup'
      };
    }

    // Create user record
    const { error: userError } = await supabase
      .from('users')
      .insert({
        id: authData.user.id,
        email,
        role: 'student'
      });

    if (userError) {
      // Clean up auth user if user record creation fails
      await supabase.auth.admin.deleteUser(authData.user.id);
      return {
        success: false,
        error: userError,
        message: 'Failed to create user profile'
      };
    }

    // Create student record
    const { error: studentError } = await supabase
      .from('students')
      .insert({
        user_id: authData.user.id,
        full_name: fullName,
        email,
        department_id: department,
        enrollment_status: 'active'
      });

    if (studentError) {
      // Clean up if student record creation fails
      await supabase.from('users').delete().eq('id', authData.user.id);
      await supabase.auth.admin.deleteUser(authData.user.id);
      return {
        success: false,
        error: studentError,
        message: 'Failed to create student profile'
      };
    }

    return {
      success: true,
      user: {
        id: authData.user.id,
        email,
        role: 'student',
        created_at: authData.user.created_at,
        updated_at: authData.user.updated_at
      },
      message: 'Student account created successfully. Please check your email to verify.'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      message: 'Signup failed'
    };
  }
}

/**
 * Sign in a user
 * @param email User email
 * @param password User password
 * @returns AuthResponse with user data or error
 */
export async function signInUser(
  email: string,
  password: string
): Promise<AuthResponse> {
  try {
    if (!email || !password) {
      return {
        success: false,
        error: 'Email and password are required',
        message: 'Missing credentials'
      };
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) {
      return {
        success: false,
        error,
        message: 'Invalid email or password'
      };
    }

    if (!data.user) {
      return {
        success: false,
        error: 'No user found',
        message: 'Authentication failed'
      };
    }

    // Fetch user details
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', data.user.id)
      .single();

    if (userError || !userData) {
      return {
        success: false,
        error: userError || 'User profile not found',
        message: 'Failed to load user profile'
      };
    }

    return {
      success: true,
      user: userData as User,
      message: 'Signed in successfully'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      message: 'Sign in failed'
    };
  }
}

/**
 * Sign out the current user
 * @returns AuthResponse indicating success or error
 */
export async function signOutUser(): Promise<AuthResponse> {
  try {
    const { error } = await supabase.auth.signOut();

    if (error) {
      return {
        success: false,
        error,
        message: 'Failed to sign out'
      };
    }

    return {
      success: true,
      message: 'Signed out successfully'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      message: 'Sign out failed'
    };
  }
}

/**
 * Get the current authenticated user
 * @returns Current user or null
 */
export async function getCurrentUser(): Promise<User | StudentProfile | null> {
  try {
    const { data: sessionData } = await supabase.auth.getSession();
    
    if (!sessionData.session?.user) {
      return null;
    }

    const userId = sessionData.session.user.id;

    // Fetch user details
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();

    if (userError || !userData) {
      return null;
    }

    // If student, also fetch student profile
    if (userData.role === 'student') {
      const { data: studentData } = await supabase
        .from('students')
        .select('*')
        .eq('user_id', userId)
        .single();

      if (studentData) {
        return studentData as StudentProfile;
      }
    }

    return userData as User;
  } catch (error) {
    console.error('Error fetching current user:', error);
    return null;
  }
}

/**
 * Update user profile
 * @param updates Profile updates
 * @returns AuthResponse with updated user data
 */
export async function updateUserProfile(
  updates: UpdateProfileData
): Promise<AuthResponse> {
  try {
    const { data: sessionData } = await supabase.auth.getSession();
    
    if (!sessionData.session?.user) {
      return {
        success: false,
        error: 'Not authenticated',
        message: 'User not authenticated'
      };
    }

    const userId = sessionData.session.user.id;

    // Update student profile if applicable
    if (updates.fullName || updates.enrollmentStatus) {
      const { data: studentData, error: fetchError } = await supabase
        .from('students')
        .select('*')
        .eq('user_id', userId)
        .single();

      if (fetchError) {
        return {
          success: false,
          error: fetchError,
          message: 'Failed to fetch student profile'
        };
      }

      const updateData: Record<string, any> = {};
      if (updates.fullName) updateData.full_name = updates.fullName;
      if (updates.enrollmentStatus) updateData.enrollment_status = updates.enrollmentStatus;

      const { error: updateError } = await supabase
        .from('students')
        .update(updateData)
        .eq('student_id', studentData.student_id);

      if (updateError) {
        return {
          success: false,
          error: updateError,
          message: 'Failed to update profile'
        };
      }
    }

    // Fetch updated user data
    const { data: updatedUser, error: fetchError } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();

    if (fetchError || !updatedUser) {
      return {
        success: false,
        error: fetchError,
        message: 'Failed to fetch updated profile'
      };
    }

    return {
      success: true,
      user: updatedUser as User,
      message: 'Profile updated successfully'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      message: 'Profile update failed'
    };
  }
}

/**
 * Send password reset email
 * @param email User email
 * @returns AuthResponse indicating success or error
 */
export async function resetPassword(email: string): Promise<AuthResponse> {
  try {
    if (!email) {
      return {
        success: false,
        error: 'Email is required',
        message: 'Missing email'
      };
    }

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/reset-password`
    });

    if (error) {
      return {
        success: false,
        error,
        message: 'Failed to send reset email'
      };
    }

    return {
      success: true,
      message: 'Password reset email sent. Please check your inbox.'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      message: 'Password reset failed'
    };
  }
}

/**
 * Update password
 * @param password New password
 * @returns AuthResponse indicating success or error
 */
export async function updatePassword(password: string): Promise<AuthResponse> {
  try {
    if (!password || password.length < 8) {
      return {
        success: false,
        error: 'Password must be at least 8 characters',
        message: 'Invalid password'
      };
    }

    const { error } = await supabase.auth.updateUser({
      password
    });

    if (error) {
      return {
        success: false,
        error,
        message: 'Failed to update password'
      };
    }

    return {
      success: true,
      message: 'Password updated successfully'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      message: 'Password update failed'
    };
  }
}

/**
 * Verify email with token
 * @param token Verification token from email
 * @returns AuthResponse indicating success or error
 */
export async function verifyEmail(token: string): Promise<AuthResponse> {
  try {
    if (!token) {
      return {
        success: false,
        error: 'Verification token is required',
        message: 'Missing token'
      };
    }

    const { error } = await supabase.auth.verifyOtp({
      token,
      type: 'email'
    });

    if (error) {
      return {
        success: false,
        error,
        message: 'Failed to verify email'
      };
    }

    return {
      success: true,
      message: 'Email verified successfully'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      message: 'Email verification failed'
    };
  }
}

/**
 * Set up real-time listener for auth changes
 * @param callback Function to call when auth state changes
 * @returns Unsubscribe function
 */
export function onAuthStateChange(
  callback: (user: User | null) => void
): (() => void) {
  const { data: authListener } = supabase.auth.onAuthStateChange(
    async (event, session) => {
      if (session?.user) {
        const currentUser = await getCurrentUser();
        callback(currentUser as User | null);
      } else {
        callback(null);
      }
    }
  );

  return () => {
    authListener?.subscription.unsubscribe();
  };
}
