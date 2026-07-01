-- ============================================================================
-- University Clearance System - Initial Schema Migration
-- ============================================================================

-- ============================================================================
-- 1. USERS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.users (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('student', 'department_head', 'admin')),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT users_not_deleted CHECK (deleted_at IS NULL)
);

CREATE INDEX idx_users_email ON public.users(email);
CREATE INDEX idx_users_role ON public.users(role);
CREATE INDEX idx_users_created_at ON public.users(created_at);

-- ============================================================================
-- 2. DEPARTMENTS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.departments (
  department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  head_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT departments_not_deleted CHECK (deleted_at IS NULL)
);

CREATE INDEX idx_departments_head_id ON public.departments(head_id);
CREATE INDEX idx_departments_name ON public.departments(name);

-- ============================================================================
-- 3. STUDENTS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.students (
  student_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  department_id UUID NOT NULL REFERENCES public.departments(department_id) ON DELETE RESTRICT,
  enrollment_status TEXT NOT NULL CHECK (enrollment_status IN ('active', 'inactive', 'graduated', 'suspended')),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT students_not_deleted CHECK (deleted_at IS NULL)
);

CREATE INDEX idx_students_user_id ON public.students(user_id);
CREATE INDEX idx_students_department_id ON public.students(department_id);
CREATE INDEX idx_students_email ON public.students(email);
CREATE INDEX idx_students_enrollment_status ON public.students(enrollment_status);

-- ============================================================================
-- 4. CLEARANCE REQUIREMENTS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.clearance_requirements (
  requirement_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  department_id UUID NOT NULL REFERENCES public.departments(department_id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  required_for_graduation BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT clearance_requirements_not_deleted CHECK (deleted_at IS NULL),
  UNIQUE(department_id, name)
);

CREATE INDEX idx_clearance_requirements_department_id ON public.clearance_requirements(department_id);
CREATE INDEX idx_clearance_requirements_required_for_graduation ON public.clearance_requirements(required_for_graduation);

-- ============================================================================
-- 5. CLEARANCE PROGRESS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.clearance_progress (
  progress_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id UUID NOT NULL REFERENCES public.students(student_id) ON DELETE CASCADE,
  requirement_id UUID NOT NULL REFERENCES public.clearance_requirements(requirement_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')) DEFAULT 'pending',
  signed_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
  signed_at TIMESTAMP WITH TIME ZONE,
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT clearance_progress_not_deleted CHECK (deleted_at IS NULL),
  UNIQUE(student_id, requirement_id),
  CONSTRAINT valid_signed_state CHECK (
    (status = 'pending' AND signed_by IS NULL AND signed_at IS NULL) OR
    (status IN ('approved', 'rejected') AND signed_by IS NOT NULL AND signed_at IS NOT NULL)
  )
);

CREATE INDEX idx_clearance_progress_student_id ON public.clearance_progress(student_id);
CREATE INDEX idx_clearance_progress_requirement_id ON public.clearance_progress(requirement_id);
CREATE INDEX idx_clearance_progress_status ON public.clearance_progress(status);
CREATE INDEX idx_clearance_progress_signed_by ON public.clearance_progress(signed_by);
CREATE INDEX idx_clearance_progress_created_at ON public.clearance_progress(created_at);

-- ============================================================================
-- 6. AUDIT LOG TABLE (Append-only)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.audit_log (
  log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  table_name TEXT NOT NULL,
  record_id UUID NOT NULL,
  old_value JSONB,
  new_value JSONB,
  ip_address INET,
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  CONSTRAINT audit_log_immutable CHECK (timestamp = DATE_TRUNC('millisecond', timestamp))
);

CREATE INDEX idx_audit_log_user_id ON public.audit_log(user_id);
CREATE INDEX idx_audit_log_table_name ON public.audit_log(table_name);
CREATE INDEX idx_audit_log_record_id ON public.audit_log(record_id);
CREATE INDEX idx_audit_log_timestamp ON public.audit_log(timestamp DESC);

-- ============================================================================
-- 7. DISPUTES TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.disputes (
  dispute_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id UUID NOT NULL REFERENCES public.students(student_id) ON DELETE CASCADE,
  requirement_id UUID NOT NULL REFERENCES public.clearance_requirements(requirement_id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'resolved', 'escalated')) DEFAULT 'open',
  resolved_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
  resolution_notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMP WITH TIME ZONE,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT disputes_not_deleted CHECK (deleted_at IS NULL),
  CONSTRAINT valid_resolved_state CHECK (
    (status = 'open' AND resolved_by IS NULL AND resolved_at IS NULL) OR
    (status IN ('resolved', 'escalated') AND resolved_by IS NOT NULL AND resolved_at IS NOT NULL)
  )
);

CREATE INDEX idx_disputes_student_id ON public.disputes(student_id);
CREATE INDEX idx_disputes_requirement_id ON public.disputes(requirement_id);
CREATE INDEX idx_disputes_status ON public.disputes(status);
CREATE INDEX idx_disputes_created_at ON public.disputes(created_at);
CREATE INDEX idx_disputes_resolved_by ON public.disputes(resolved_by);

-- ============================================================================
-- 8. NOTIFICATIONS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.notifications (
  notification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  message TEXT NOT NULL,
  read_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  CONSTRAINT notification_type_check CHECK (type IN ('clearance_update', 'dispute_resolved', 'requirement_added', 'general'))
);

CREATE INDEX idx_notifications_user_id ON public.notifications(user_id);
CREATE INDEX idx_notifications_read_at ON public.notifications(read_at);
CREATE INDEX idx_notifications_created_at ON public.notifications(created_at DESC);
CREATE INDEX idx_notifications_unread ON public.notifications(user_id, read_at) WHERE read_at IS NULL;

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_departments_updated_at BEFORE UPDATE ON public.departments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_students_updated_at BEFORE UPDATE ON public.students
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clearance_requirements_updated_at BEFORE UPDATE ON public.clearance_requirements
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clearance_progress_updated_at BEFORE UPDATE ON public.clearance_progress
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_disputes_updated_at BEFORE UPDATE ON public.disputes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notifications_updated_at BEFORE UPDATE ON public.notifications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- GRANTS
-- ============================================================================
GRANT USAGE ON SCHEMA public TO postgres, anon, authenticated, service_role;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres, service_role;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres, service_role;
