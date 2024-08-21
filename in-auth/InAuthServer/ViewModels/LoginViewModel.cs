using System.ComponentModel.DataAnnotations;

namespace InAuthServer.ViewModels;

public class LoginViewModel
{
    [Required]
    public string Username { get; set; } = default!;
    [Required]
    public string Password { get; set; } = default!;
    public string? ReturnUrl { get; set; }
}
