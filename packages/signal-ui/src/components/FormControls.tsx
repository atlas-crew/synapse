import React from 'react';
import { colors, fontFamily, fontWeight, spacing, transitions } from '../tokens/tokens';

/**
 * Input — Text input with label, helper text, and error states.
 * Select — Dropdown select with brand styling.
 */

interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
  label?: string;
  error?: string;
  helper?: string;
  icon?: React.ReactNode;
  suffix?: React.ReactNode;
  multiline?: boolean;
  rows?: number;
  size?: 'sm' | 'md' | 'lg';
  fill?: boolean;
  containerStyle?: React.CSSProperties;
}

const inputSizes = {
  sm: { fontSize: '13px', padding: '8px 12px', height: '32px' },
  md: { fontSize: '14px', padding: '10px 16px', height: '40px' },
  lg: { fontSize: '16px', padding: '12px 16px', height: '48px' },
};

export const Input: React.FC<InputProps> = ({
  label, error, helper, icon, suffix, multiline, rows = 3,
  size = 'md', fill, containerStyle, style, ...rest
}) => {
  const s = inputSizes[size];
  const borderColor = error ? colors.red : `rgba(255,255,255,0.15)`;
  const focusBorderColor = error ? colors.red : colors.skyBlue;

  const inputStyle: React.CSSProperties = {
    fontFamily, fontWeight: fontWeight.regular, fontSize: s.fontSize,
    padding: s.padding,
    paddingLeft: icon ? '36px' : s.padding.split(' ')[1] || s.padding,
    paddingRight: suffix ? '36px' : s.padding.split(' ')[1] || s.padding,
    height: multiline ? 'auto' : s.height,
    background: colors.card.dark, color: '#F0F4F8',
    border: `1px solid ${borderColor}`, borderRadius: 0,
    width: '100%', outline: 'none',
    transition: `border-color ${transitions.fast}`,
    resize: multiline ? 'vertical' : undefined,
    ...style,
  };

  const handleFocus = (e: React.FocusEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    e.currentTarget.style.borderColor = focusBorderColor;
    rest.onFocus?.(e as any);
  };

  const handleBlur = (e: React.FocusEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    e.currentTarget.style.borderColor = borderColor;
    rest.onBlur?.(e as any);
  };

  return (
    <div style={{ width: fill ? '100%' : undefined, ...containerStyle }}>
      {label && (
        <label style={{
          fontFamily, fontWeight: fontWeight.medium, fontSize: '12px',
          color: '#F0F4F8', display: 'block', marginBottom: spacing.xs,
        }}>
          {label}
        </label>
      )}
      <div style={{ position: 'relative' }}>
        {icon && (
          <span style={{
            position: 'absolute', left: '12px', top: '50%',
            transform: 'translateY(-50%)', color: colors.gray.mid,
            fontSize: '14px', pointerEvents: 'none',
          }}>
            {icon}
          </span>
        )}
        {multiline ? (
          <textarea
            rows={rows} style={inputStyle}
            onFocus={handleFocus as any} onBlur={handleBlur as any}
            {...(rest as any)}
          />
        ) : (
          <input style={inputStyle} onFocus={handleFocus} onBlur={handleBlur} {...rest} />
        )}
        {suffix && (
          <span style={{
            position: 'absolute', right: '12px', top: '50%',
            transform: 'translateY(-50%)',
          }}>
            {suffix}
          </span>
        )}
      </div>
      {(error || helper) && (
        <span style={{
          fontFamily, fontSize: '12px',
          color: error ? colors.red : colors.gray.mid,
          marginTop: '4px', display: 'block',
        }}>
          {error || helper}
        </span>
      )}
    </div>
  );
};

Input.displayName = 'Input';

interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

interface SelectProps extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'size'> {
  label?: string;
  options: SelectOption[];
  error?: string;
  helper?: string;
  placeholder?: string;
  size?: 'sm' | 'md' | 'lg';
  fill?: boolean;
  containerStyle?: React.CSSProperties;
}

export const Select: React.FC<SelectProps> = ({
  label, options, error, helper, placeholder,
  size = 'md', fill, containerStyle, style, ...rest
}) => {
  const s = inputSizes[size];
  const borderColor = error ? colors.red : 'rgba(255,255,255,0.15)';

  return (
    <div style={{ width: fill ? '100%' : undefined, ...containerStyle }}>
      {label && (
        <label style={{
          fontFamily, fontWeight: fontWeight.medium, fontSize: '12px',
          color: '#F0F4F8', display: 'block', marginBottom: spacing.xs,
        }}>
          {label}
        </label>
      )}
      <select
        style={{
          fontFamily, fontWeight: fontWeight.regular, fontSize: s.fontSize,
          padding: s.padding, height: s.height,
          background: colors.card.dark, color: '#F0F4F8',
          border: `1px solid ${borderColor}`, borderRadius: 0,
          width: '100%', outline: 'none', cursor: 'pointer',
          appearance: 'none',
          backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%237F7F7F' d='M6 8L1 3h10z'/%3E%3C/svg%3E")`,
          backgroundRepeat: 'no-repeat',
          backgroundPosition: 'right 12px center',
          paddingRight: '36px',
          transition: `border-color ${transitions.fast}`,
          ...style,
        }}
        onFocus={(e) => (e.currentTarget.style.borderColor = error ? colors.red : colors.skyBlue)}
        onBlur={(e) => (e.currentTarget.style.borderColor = borderColor)}
        {...rest}
      >
        {placeholder && <option value="" disabled>{placeholder}</option>}
        {options.map((opt) => (
          <option key={opt.value} value={opt.value} disabled={opt.disabled}>{opt.label}</option>
        ))}
      </select>
      {(error || helper) && (
        <span style={{
          fontFamily, fontSize: '12px',
          color: error ? colors.red : colors.gray.mid,
          marginTop: '4px', display: 'block',
        }}>
          {error || helper}
        </span>
      )}
    </div>
  );
};

Select.displayName = 'Select';

