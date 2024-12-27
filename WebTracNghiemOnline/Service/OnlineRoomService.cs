using AutoMapper;
using WebTracNghiemOnline.DTO;
using WebTracNghiemOnline.Exceptions;
using WebTracNghiemOnline.Models;
using WebTracNghiemOnline.Repository;

namespace WebTracNghiemOnline.Service
{

    public interface IOnlineRoomService
    {
        Task<OnlineRoom> CreateRoomAsync(string hostUserId, string roomName);
        Task<UserOnlineRoom> JoinRoomAsync(string userId, string roomCode);
        Task<bool> LeaveRoomAsync(string userId, string roomCode);
        Task<OnlineRoom?> GetRoomByCodeAsync(string roomCode);
        Task<Exercise> CreateExerciseAsync(string userId, int roomId, CreateExerciseDto request);
        Task<List<OnlineRoom>> GetUserRoomsAsync(string userId);
        Task<GradeResultDto> GradeExerciseAsync(string userId, int exerciseId, List<UserAnswerDto> userAnswers);
        Task<List<Exercise>> GetExercisesInRoomAsync(int roomId);
        Task<Exercise?> GetExerciseDetailsAsync(int exerciseId);
        Task<bool> IsUserOwnerInRoomAsync(string userId, int roomId);
        Task<List<ExerciseHistoryDto>> GetUserExerciseHistoriesInRoomAsync(string userId, int roomId);
        Task<Dictionary<string, List<ExerciseHistoryDto>>> GetAllExerciseHistoriesByExercisesAsync(int roomId);
        Task<List<ExerciseHistoryDto>> GetHighestScoreHistoriesByRoomAsync(int roomId);
    }

    public class OnlineRoomService : IOnlineRoomService
    {
        private readonly IOnlineRoomRepository _repository;
        private readonly IMapper _mapper;
        private readonly IEmailService _emailService;


        public OnlineRoomService(IOnlineRoomRepository repository, IMapper mapper, IEmailService emailService)
        {
            _repository = repository;
            _mapper = mapper;
            _emailService = emailService;
        }

        public async Task<OnlineRoom> CreateRoomAsync(string hostUserId, string roomName)
        {
            // Generate unique room code
            string roomCode;
            do
            {
                roomCode = GenerateRoomCode();
            } while (await _repository.GetRoomByCodeAsync(roomCode) != null);

            // Create new room
            var room = new OnlineRoom
            {
                RoomCode = roomCode,
                RoomName = roomName, // Sử dụng roomName từ người dùng
                CreatedAt = DateTime.UtcNow
            };

            var createdRoom = await _repository.CreateRoomAsync(room);

            // Add owner to the room
            var ownerEntry = new UserOnlineRoom
            {
                UserId = hostUserId,
                OnlineRoomId = createdRoom.OnlineRoomId,
                Role = UserRole.Owner,
                JoinedAt = DateTime.UtcNow
            };
            await _repository.AddUserToRoomAsync(ownerEntry);

            return createdRoom;
        }
        public async Task<List<OnlineRoom>> GetUserRoomsAsync(string userId)
        {
            return await _repository.GetUserRoomsAsync(userId);
        }


        public async Task<UserOnlineRoom> JoinRoomAsync(string userId, string roomCode)
        {
            // Find room by code
            var room = await _repository.GetRoomByCodeAsync(roomCode);
            if (room == null)
                throw new RoomNotFoundException();

            // Check if user is already in the room
            if (await _repository.IsUserInRoomAsync(userId, room.OnlineRoomId))
                throw new UserAlreadyInRoomException();

            // Add user to room
            var userOnlineRoom = new UserOnlineRoom
            {
                UserId = userId,
                OnlineRoomId = room.OnlineRoomId,
                Role = UserRole.Member,
                JoinedAt = DateTime.UtcNow
            };

            return await _repository.AddUserToRoomAsync(userOnlineRoom);
        }



        private string GenerateRoomCode()
        {
            return Guid.NewGuid().ToString("N").Substring(0, 6).ToUpper();
        }

        public async Task<bool> LeaveRoomAsync(string userId, string roomCode)
        {
            var room = await _repository.GetRoomByCodeAsync(roomCode);
            if (room == null)
                throw new RoomNotFoundException();

            return await _repository.LeaveRoomAsync(userId, room.OnlineRoomId);
        }
        public async Task<OnlineRoom?> GetRoomByCodeAsync(string roomCode)
        {
            return await _repository.GetRoomByCodeAsync(roomCode);
        }


        public async Task<Exercise> CreateExerciseAsync(string userId, int roomId, CreateExerciseDto request)
        {
            // Kiểm tra người dùng có trong phòng và có vai trò là Owner không
            var userRoom = await _repository.GetUserInRoomAsync(userId, roomId);
            if (userRoom == null || userRoom.Role != UserRole.Owner)
            {
                throw new UnauthorizedAccessException("Only the owner can create exercises.");
            }

            // Kiểm tra thời gian bắt đầu và kết thúc
            if (request.EndTime <= request.StartTime)
            {
                throw new ArgumentException("The end time must be greater than the start time of the exercise.");
            }

            // Ánh xạ DTO thành Entity
            var exercise = _mapper.Map<Exercise>(request);
            exercise.OnlineRoomId = roomId;

            var createdExercise = await _repository.AddExerciseAsync(exercise);

            // Gửi email thông báo
            var usersInRoom = await _repository.GetUsersInRoomAsync(roomId); // Lấy danh sách thành viên trong phòng
            var emailTasks = usersInRoom.Select(user =>
                _emailService.SendEmailAsync(
                    user.User.Email, // Địa chỉ email của thành viên
                    "Bài tập mới đã được thêm vào phòng học",
                    $"Xin chào {user.User.FullName},<br/><br/>" +
                    $"Bài tập <strong>{request.ExerciseName}</strong> đã được thêm vào phòng <strong>{userRoom.OnlineRoom.RoomName}</strong>. " +
                    $"Vui lòng truy cập để hoàn thành bài tập.<br/><br/>" +
                    $"Thời gian bắt đầu: {request.StartTime}<br/>" +
                    $"Thời gian kết thúc: {request.EndTime}<br/><br/>" +
                    "Trân trọng,<br/>Web Trắc Nghiệm Online"
                )
            );
            await Task.WhenAll(emailTasks);

            return createdExercise;
        }
        public async Task<GradeResultDto> GradeExerciseAsync(string userId, int exerciseId, List<UserAnswerDto> userAnswers)
        {
            var exerciseQuestions = await _repository.GetQuestionsWithAnswersAsync(exerciseId);
            if (exerciseQuestions == null || !exerciseQuestions.Any())
            {
                throw new ArgumentException("Exercise does not exist or has no questions.");
            }

            int totalQuestions = exerciseQuestions.Count;
            int correctAnswers = 0;

            foreach (var question in exerciseQuestions)
            {
                var userAnswer = userAnswers.FirstOrDefault(ua => ua.QuestionId == question.ExerciseQuestionId);
                if (userAnswer == null || userAnswer.AnswerIds == null || !userAnswer.AnswerIds.Any())
                {
                    continue; // Không trả lời câu hỏi hoặc câu trả lời không hợp lệ
                }

                var correctAnswerIds = question.ExerciseAnswers.Where(a => a.IsCorrect).Select(a => a.ExerciseAnswerId).ToList();
                if (correctAnswerIds.SequenceEqual(userAnswer.AnswerIds.OrderBy(x => x)))
                {
                    correctAnswers++;
                }
            }

            var score = (double)correctAnswers / totalQuestions * 100;

            await _repository.AddExerciseHistoryAsync(new ExerciseHistory
            {
                UserId = userId,
                ExerciseId = exerciseId,
                Score = (int)score,
                StartTime = DateTime.UtcNow,
                EndTime = DateTime.UtcNow,
                IsCompleted = true
            });

            return new GradeResultDto
            {
                TotalQuestions = totalQuestions,
                CorrectAnswers = correctAnswers,
                Score = score
            };
        }

        public async Task<List<Exercise>> GetExercisesInRoomAsync(int roomId)
        {
            return await _repository.GetExercisesInRoomAsync(roomId);
        }

        public async Task<Exercise?> GetExerciseDetailsAsync(int exerciseId)
        {
            return await _repository.GetExerciseWithQuestionsAsync(exerciseId);
        }

        public async Task<List<ExerciseHistoryDto>> GetUserExerciseHistoriesInRoomAsync(string userId, int roomId)
        {
            var histories = await _repository.GetUserExerciseHistoriesInRoomAsync(userId, roomId);
            return histories.Select(history => _mapper.Map<ExerciseHistoryDto>(history)).ToList();
        }
        public async Task<bool> IsUserOwnerInRoomAsync(string userId, int roomId)
        {
            var userRoom = await _repository.GetUserInRoomAsync(userId, roomId);
            return userRoom != null && userRoom.Role == UserRole.Owner;
        }
        public async Task<Dictionary<string, List<ExerciseHistoryDto>>> GetAllExerciseHistoriesByExercisesAsync(int roomId)
        {
            // Lấy danh sách bài tập trong phòng học
            var exercises = await _repository.GetExercisesInRoomAsync(roomId);

            // Tạo dictionary để lưu lịch sử làm bài phân loại theo bài tập
            var historiesByExercise = new Dictionary<string, List<ExerciseHistoryDto>>();

            foreach (var exercise in exercises)
            {
                // Lấy lịch sử làm bài cho từng bài tập
                var histories = await _repository.GetExerciseHistoriesByExerciseIdAsync(exercise.ExerciseId);

                // Map sang DTO
                var historyDtos = histories.Select(history => _mapper.Map<ExerciseHistoryDto>(history)).ToList();

                // Thêm vào dictionary (key là tên bài tập)
                historiesByExercise[exercise.ExerciseName] = historyDtos;
            }

            return historiesByExercise;
        }
        public async Task<List<ExerciseHistoryDto>> GetHighestScoreHistoriesByRoomAsync(int roomId)
        {
            var histories = await _repository.GetHighestScoreHistoriesByRoomAsync(roomId);

            // Map dữ liệu sang DTO
            return histories.Select(history => _mapper.Map<ExerciseHistoryDto>(history)).ToList();
        }


    }
}
