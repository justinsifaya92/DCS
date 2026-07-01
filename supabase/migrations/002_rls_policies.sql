-- ============================================================================
-- University Clearance System - Row-Level Security (RLS) Policies
-- ============================================================================

-- ============================================================================
-- ENABLE RLS ON ALL TABLES
-- ============================================================================
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.departments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clearance_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clearance_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.disputes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 1. USERS TABLE POLICIES
-- ============================================================================

-- Admins can view all users
CREATE POLICY "Admins can view all users" ON public.users
FOR SELECT
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- Users can view their own record
CREATE POLICY "Users can view own user record" ON public.users
FOR SELECT
USING (auth.uid() = id);

-- Users can update their own record
CREATE POLICY "Users can update own user record" ON public.users
FOR UPDATE
USING (auth.uid() = id)
WITH CHECK (
    auth.uid() = id AND 
    role = (SELECT role FROM public.users WHERE id = auth.uid())
);

-- Admins can update any user
CREATE POLICY "Admins can update any user" ON public.users
FOR UPDATE
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- Prevent direct deletion (use soft delete)
CREATE POLICY "Prevent user deletion" ON public.users
FOR DELETE
USING (FALSE);

-- ============================================================================
-- 2. STUDENTS TABLE POLICIES
-- ============================================================================

-- Students can view their own record
CREATE POLICY "Students can view own student record" ON public.students
FOR SELECT
USING (
    user_id = auth.uid() OR
    user_id IN (
        SELECT user_id FROM public.students WHERE student_id = 
        (SELECT student_id FROM public.students WHERE user_id = auth.uid())
    )
);

-- Department heads can view students in their department
CREATE POLICY "Department heads can view their department students" ON public.students
FOR SELECT
USING (
    department_id IN (
        SELECT department_id FROM public.departments 
        WHERE head_id = auth.uid() AND deleted_at IS NULL
    )
);

-- Admins can view all students
CREATE POLICY "Admins can view all students" ON public.students
FOR SELECT
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- Students can update their own profile (limited fields)
CREATE POLICY "Students can update own profile" ON public.students
FOR UPDATE
USING (user_id = auth.uid())
WITH CHECK (
    user_id = auth.uid() AND
    user_id = (SELECT user_id FROM public.students WHERE student_id = OLD.student_id)
);

-- Admins can update any student
CREATE POLICY "Admins can update any student" ON public.students
FOR UPDATE
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- ============================================================================
-- 3. DEPARTMENTS TABLE POLICIES
-- ============================================================================

-- Everyone (authenticated) can view departments
CREATE POLICY "Authenticated users can view departments" ON public.departments
FOR SELECT
USING (auth.role() = 'authenticated' AND deleted_at IS NULL);

-- Department heads can update their own department
CREATE POLICY "Department heads can update their department" ON public.departments
FOR UPDATE
USING (
    head_id = auth.uid() AND deleted_at IS NULL
)
WITH CHECK (
    head_id = auth.uid()
);

-- Admins can update any department
CREATE POLICY "Admins can update any department" ON public.departments
FOR UPDATE
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- ============================================================================
-- 4. CLEARANCE REQUIREMENTS TABLE POLICIES
-- ============================================================================

-- Everyone can view clearance requirements for their department
CREATE POLICY "Users can view clearance requirements" ON public.clearance_requirements
FOR SELECT
USING (
    deleted_at IS NULL AND (
        -- Students can see requirements for their department
        department_id IN (
            SELECT department_id FROM public.students WHERE user_id = auth.uid()
        ) OR
        -- Department heads can see their department's requirements
        department_id IN (
            SELECT department_id FROM public.departments WHERE head_id = auth.uid()
        ) OR
        -- Admins can see all requirements
        auth.uid() IN (
            SELECT id FROM public.users WHERE role = 'admin'
        )
    )
);

-- Department heads can create requirements for their department
CREATE POLICY "Department heads can create requirements" ON public.clearance_requirements
FOR INSERT
WITH CHECK (
    department_id IN (
        SELECT department_id FROM public.departments 
        WHERE head_id = auth.uid() AND deleted_at IS NULL
    )
);

-- Department heads can update their department's requirements
CREATE POLICY "Department heads can update their requirements" ON public.clearance_requirements
FOR UPDATE
USING (
    department_id IN (
        SELECT department_id FROM public.departments 
        WHERE head_id = auth.uid() AND deleted_at IS NULL
    )
)
WITH CHECK (
    department_id IN (
        SELECT department_id FROM public.departments 
        WHERE head_id = auth.uid() AND deleted_at IS NULL
    )
);

-- Admins can manage all requirements
CREATE POLICY "Admins can manage all requirements" ON public.clearance_requirements
FOR ALL
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- ============================================================================
-- 5. CLEARANCE PROGRESS TABLE POLICIES
-- ============================================================================

-- Students can view their own clearance progress
CREATE POLICY "Students can view own clearance progress" ON public.clearance_progress
FOR SELECT
USING (
    student_id IN (
        SELECT student_id FROM public.students WHERE user_id = auth.uid()
    )
);

-- Department heads can view clearance progress for their department students
CREATE POLICY "Department heads can view their department's clearance progress" ON public.clearance_progress
FOR SELECT
USING (
    student_id IN (
        SELECT student_id FROM public.students 
        WHERE department_id IN (
            SELECT department_id FROM public.departments 
            WHERE head_id = auth.uid() AND deleted_at IS NULL
        )
    )
);

-- Admins can view all clearance progress
CREATE POLICY "Admins can view all clearance progress" ON public.clearance_progress
FOR SELECT
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- Department heads can approve/reject clearance for their department
CREATE POLICY "Department heads can approve/reject clearance" ON public.clearance_progress
FOR UPDATE
USING (
    student_id IN (
        SELECT student_id FROM public.students 
        WHERE department_id IN (
            SELECT department_id FROM public.departments 
            WHERE head_id = auth.uid() AND deleted_at IS NULL
        )
    )
)
WITH CHECK (
    student_id IN (
        SELECT student_id FROM public.students 
        WHERE department_id IN (
            SELECT department_id FROM public.departments 
            WHERE head_id = auth.uid() AND deleted_at IS NULL
        )
    ) AND
    signed_by = auth.uid()
);

-- Admins can manage all clearance progress
CREATE POLICY "Admins can manage all clearance progress" ON public.clearance_progress
FOR ALL
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- ============================================================================
-- 6. AUDIT LOG TABLE POLICIES (Append-only)
-- ============================================================================

-- Everyone can view audit logs for their own actions
CREATE POLICY "Users can view their own audit logs" ON public.audit_log
FOR SELECT
USING (user_id = auth.uid());

-- Department heads can view audit logs for their department's actions
CREATE POLICY "Department heads can view department audit logs" ON public.audit_log
FOR SELECT
USING (
    table_name IN ('clearance_progress', 'students') AND
    record_id IN (
        SELECT progress_id FROM public.clearance_progress
        WHERE student_id IN (
            SELECT student_id FROM public.students 
            WHERE department_id IN (
                SELECT department_id FROM public.departments 
                WHERE head_id = auth.uid()
            )
        )
    )
);

-- Admins can view all audit logs
CREATE POLICY "Admins can view all audit logs" ON public.audit_log
FOR SELECT
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- Service role can insert audit logs (via triggers/functions)
CREATE POLICY "Audit logs are append-only" ON public.audit_log
FOR INSERT
WITH CHECK (true);

-- Prevent updates and deletes on audit logs
CREATE POLICY "Audit logs cannot be updated" ON public.audit_log
FOR UPDATE
USING (FALSE);

CREATE POLICY "Audit logs cannot be deleted" ON public.audit_log
FOR DELETE
USING (FALSE);

-- ============================================================================
-- 7. DISPUTES TABLE POLICIES
-- ============================================================================

-- Students can view their own disputes
CREATE POLICY "Students can view own disputes" ON public.disputes
FOR SELECT
USING (
    student_id IN (
        SELECT student_id FROM public.students WHERE user_id = auth.uid()
    )
);

-- Students can create disputes
CREATE POLICY "Students can create disputes" ON public.disputes
FOR INSERT
WITH CHECK (
    student_id IN (
        SELECT student_id FROM public.students WHERE user_id = auth.uid()
    )
);

-- Department heads can view disputes for their department students
CREATE POLICY "Department heads can view department disputes" ON public.disputes
FOR SELECT
USING (
    student_id IN (
        SELECT student_id FROM public.students 
        WHERE department_id IN (
            SELECT department_id FROM public.departments 
            WHERE head_id = auth.uid() AND deleted_at IS NULL
        )
    )
);

-- Department heads can update disputes for their department
CREATE POLICY "Department heads can update department disputes" ON public.disputes
FOR UPDATE
USING (
    student_id IN (
        SELECT student_id FROM public.students 
        WHERE department_id IN (
            SELECT department_id FROM public.departments 
            WHERE head_id = auth.uid() AND deleted_at IS NULL
        )
    )
)
WITH CHECK (
    resolved_by = auth.uid() OR (
        resolved_by IS NULL AND status = 'open'
    )
);

-- Admins can manage all disputes
CREATE POLICY "Admins can manage all disputes" ON public.disputes
FOR ALL
USING (
    auth.uid() IN (
        SELECT id FROM public.users WHERE role = 'admin' AND deleted_at IS NULL
    )
);

-- ============================================================================
-- 8. NOTIFICATIONS TABLE POLICIES
-- ============================================================================

-- Users can only view their own notifications
CREATE POLICY "Users can view own notifications" ON public.notifications
FOR SELECT
USING (user_id = auth.uid());

-- Users can update their own notifications (mark as read)
CREATE POLICY "Users can update own notifications" ON public.notifications
FOR UPDATE
USING (user_id = auth.uid())
WITH CHECK (user_id = auth.uid());

-- System can insert notifications (via triggers/functions)
CREATE POLICY "System can create notifications" ON public.notifications
FOR INSERT
WITH CHECK (true);

-- Users cannot delete their own notifications (soft delete only)
CREATE POLICY "Prevent notification deletion" ON public.notifications
FOR DELETE
USING (FALSE);

-- ============================================================================
-- HELPER FUNCTION FOR AUDIT LOGGING
-- ============================================================================

CREATE OR REPLACE FUNCTION audit_log_changes()
RETURNS TRIGGER AS $$
DECLARE
    v_user_id UUID;
    v_action TEXT;
    v_old_value JSONB;
    v_new_value JSONB;
BEGIN
    v_user_id := auth.uid();
    
    IF TG_OP = 'DELETE' THEN
        v_action := 'DELETE';
        v_old_value := row_to_json(OLD);
        v_new_value := NULL;
        PERFORM INSERT INTO public.audit_log (user_id, action, table_name, record_id, old_value, new_value)
        VALUES (v_user_id, v_action, TG_TABLE_NAME, OLD.id, v_old_value, v_new_value);
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        v_action := 'UPDATE';
        v_old_value := row_to_json(OLD);
        v_new_value := row_to_json(NEW);
        PERFORM INSERT INTO public.audit_log (user_id, action, table_name, record_id, old_value, new_value)
        VALUES (v_user_id, v_action, TG_TABLE_NAME, NEW.id, v_old_value, v_new_value);
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        v_action := 'INSERT';
        v_old_value := NULL;
        v_new_value := row_to_json(NEW);
        PERFORM INSERT INTO public.audit_log (user_id, action, table_name, record_id, old_value, new_value)
        VALUES (v_user_id, v_action, TG_TABLE_NAME, NEW.id, v_old_value, v_new_value);
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Attach audit logging to clearance_progress updates
CREATE TRIGGER audit_clearance_progress
AFTER INSERT OR UPDATE OR DELETE ON public.clearance_progress
FOR EACH ROW
EXECUTE FUNCTION audit_log_changes();

-- Attach audit logging to disputes updates
CREATE TRIGGER audit_disputes
AFTER INSERT OR UPDATE OR DELETE ON public.disputes
FOR EACH ROW
EXECUTE FUNCTION audit_log_changes();
